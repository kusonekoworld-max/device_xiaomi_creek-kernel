#!/usr/bin/env python3
"""Fetch one or more partitions out of a remote A/B OTA zip using HTTP range requests.

Enhanced from ~/itel-rs4-devicetree/tools/ota_vendor_probe.py:
  - Coalesces contiguous payload.bin extents into fewer HTTP Range requests
  - Truncates/pads the output file to new_partition_info.size (handles trailing ZERO extents)
  - Verifies the reconstructed image's SHA-256 against new_partition_info.hash in the CrAU manifest
"""
import argparse
import bz2
import hashlib
import io
import lzma
import os
import sys
import urllib.request
import zipfile

UA = {"User-Agent": "Mozilla/5.0"}
REPLACE, REPLACE_BZ, ZERO, DISCARD, REPLACE_XZ = 0, 1, 6, 7, 8


def _open(url, extra=None):
    h = dict(UA)
    if extra:
        h.update(extra)
    return urllib.request.urlopen(urllib.request.Request(url, headers=h), timeout=120)


class HttpFile(io.RawIOBase):
    """Seekable read-only file over HTTP range requests, so zipfile can drive it."""

    def __init__(self, url):
        self.url = url
        self.pos = 0
        self.size = int(_open(url, {"Range": "bytes=0-0"}).headers["Content-Range"].split("/")[1])

    def seek(self, off, whence=0):
        self.pos = off if whence == 0 else (self.pos + off if whence == 1 else self.size + off)
        return self.pos

    def tell(self):
        return self.pos

    def readable(self):
        return True

    def seekable(self):
        return True

    def read(self, n=-1):
        if n < 0:
            n = self.size - self.pos
        if n == 0 or self.pos >= self.size:
            return b""
        end = min(self.pos + n, self.size) - 1
        data = _open(self.url, {"Range": f"bytes={self.pos}-{end}"}).read()
        self.pos += len(data)
        return data


def _varint(b, i):
    r = s = 0
    while True:
        x = b[i]
        i += 1
        r |= (x & 0x7F) << s
        if not x & 0x80:
            return r, i
        s += 7


def _fields(b):
    i, n = 0, len(b)
    while i < n:
        key, i = _varint(b, i)
        fn, wt = key >> 3, key & 7
        if wt == 0:
            v, i = _varint(b, i)
            yield fn, v
        elif wt == 2:
            ln, i = _varint(b, i)
            yield fn, b[i:i + ln]
            i += ln
        elif wt == 1:
            yield fn, b[i:i + 8]
            i += 8
        elif wt == 5:
            yield fn, b[i:i + 4]
            i += 4
        else:
            raise ValueError(f"bad wire type {wt}")


def _extents(buf):
    start = num = 0
    for fn, v in _fields(buf):
        if fn == 1:
            start = v
        elif fn == 2:
            num = v
    return start, num


def extract_partition(hf, data_start, block_size, part_info, out_path, max_mb=0):
    name, p_size, p_hash, target = part_info
    limit = max_mb * 2**20 if max_mb else None
    written = fetched = skipped = 0

    # Parse all operations first
    parsed_ops = []
    for raw in target:
        op_type = data_off = data_len = 0
        dsts = []
        for of, ov in _fields(raw):
            if of == 1:
                op_type = ov
            elif of == 2:
                data_off = ov
            elif of == 3:
                data_len = ov
            elif of == 6:
                dsts.append(_extents(ov))
        first = dsts[0][0] * block_size if dsts else 0
        if limit and first >= limit:
            skipped += 1
            continue
        parsed_ops.append((op_type, data_off, data_len, dsts))

    # Check if all data-bearing ops are contiguous so we can fetch in 16 MiB chunks
    data_ops = [(op_type, data_off, data_len, dsts) for (op_type, data_off, data_len, dsts) in parsed_ops
                if op_type not in (ZERO, DISCARD) and data_len > 0]

    with open(out_path, "wb") as out:
        if not limit and p_size > 0:
            out.truncate(p_size)

        # Group contiguous data ops into batches up to 16 MiB per HTTP range request
        i = 0
        while i < len(data_ops):
            batch = [data_ops[i]]
            batch_start = data_ops[i][1]
            batch_end = batch_start + data_ops[i][2]
            j = i + 1
            while j < len(data_ops) and data_ops[j][1] == batch_end and (batch_end - batch_start + data_ops[j][2]) <= 16 * 2**20:
                batch.append(data_ops[j])
                batch_end += data_ops[j][2]
                j += 1

            hf.seek(data_start + batch_start)
            batch_blob = hf.read(batch_end - batch_start)
            if len(batch_blob) != (batch_end - batch_start):
                sys.exit(f"short read on {name}: expected {batch_end - batch_start}, got {len(batch_blob)}")
            fetched += len(batch_blob)

            for op_type, data_off, data_len, dsts in batch:
                rel = data_off - batch_start
                blob = batch_blob[rel:rel + data_len]
                if op_type == REPLACE_XZ:
                    blob = lzma.decompress(blob)
                elif op_type == REPLACE_BZ:
                    blob = bz2.decompress(blob)
                elif op_type != REPLACE:
                    sys.exit(f"unsupported op type {op_type} (not a full OTA?)")
                pos = 0
                for start, num in dsts:
                    chunk = blob[pos:pos + num * block_size]
                    out.seek(start * block_size)
                    out.write(chunk)
                    pos += len(chunk)
                    written = max(written, start * block_size + len(chunk))
            i = j

    if not limit and p_hash:
        h = hashlib.sha256()
        with open(out_path, "rb") as f:
            while True:
                b = f.read(4 * 2**20)
                if not b:
                    break
                h.update(b)
        actual = h.digest()
        if actual != p_hash:
            sys.exit(f"SHA256 MISMATCH for {name}: expected {p_hash.hex()}, got {actual.hex()}")
        print(f"  [{name}] {fetched/2**20:6.2f} MiB fetched -> {out_path} ({p_size/2**20:6.2f} MiB, sha256={actual.hex()[:16]}… OK)", file=sys.stderr)
    else:
        print(f"  [{name}] {fetched/2**20:6.2f} MiB fetched -> {out_path} ({written/2**20:6.2f} MiB span, {skipped} ops skipped)", file=sys.stderr)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("url")
    ap.add_argument("-p", "--partition", action="append", help="partition(s) to extract (can be repeated)")
    ap.add_argument("-o", "--out", default=None, help="output file (if single partition) or directory")
    ap.add_argument("-l", "--list", action="store_true", help="list the payload's partitions (size, sha256) and exit")
    ap.add_argument("--max-mb", type=int, default=0,
                    help="only fetch ops landing below this offset (0 = whole partition)")
    a = ap.parse_args()
    parts = a.partition or ["vendor"]

    if "://" not in a.url and os.path.exists(a.url):
        hf = open(a.url, "rb")
        hf.size = os.path.getsize(a.url)
        print(f"local zip: {hf.size/2**30:.2f} GiB", file=sys.stderr)
    else:
        hf = HttpFile(a.url)
        print(f"remote zip: {hf.size/2**30:.2f} GiB", file=sys.stderr)
    zf = zipfile.ZipFile(hf)
    info = zf.getinfo("payload.bin")
    if info.compress_type != zipfile.ZIP_STORED:
        sys.exit("payload.bin is compressed inside the zip; range extraction won't work")

    hf.seek(info.header_offset)
    hdr = hf.read(30)
    name_len = int.from_bytes(hdr[26:28], "little")
    extra_len = int.from_bytes(hdr[28:30], "little")
    payload = info.header_offset + 30 + name_len + extra_len

    hf.seek(payload)
    head = hf.read(24)
    if head[:4] != b"CrAU":
        sys.exit("payload.bin magic missing")
    version = int.from_bytes(head[4:12], "big")
    manifest_size = int.from_bytes(head[12:20], "big")
    sig_size = int.from_bytes(head[20:24], "big") if version >= 2 else 0
    hf.seek(payload + 24)
    manifest = hf.read(manifest_size)
    data_start = payload + 24 + manifest_size + sig_size

    block_size = 4096
    by_name = {}
    for fn, v in _fields(manifest):
        if fn == 3:
            block_size = v
        elif fn == 13:
            name, ops, p_size, p_hash = None, [], 0, b""
            for pf, pv in _fields(v):
                if pf == 1:
                    name = pv.decode()
                elif pf == 7:
                    for inf_f, inf_v in _fields(pv):
                        if inf_f == 1:
                            p_size = inf_v
                        elif inf_f == 2:
                            p_hash = inf_v
                elif pf == 8:
                    ops.append(pv)
            if name:
                by_name[name] = (name, p_size, p_hash, ops)

    if a.list:
        print(f"payload @ {payload}, manifest {manifest_size} B, block {block_size}, {len(by_name)} partitions", file=sys.stderr)
        for n, (_, sz, hsh, ops) in sorted(by_name.items()):
            print(f"{n}\t{sz}\t{hsh.hex()}\t{len(ops)}")
        return

    for p in parts:
        if p not in by_name:
            sys.exit(f"partition {p!r} not in payload")
        if len(parts) == 1 and a.out and not os.path.isdir(a.out):
            out_path = a.out
        else:
            out_dir = a.out or "."
            os.makedirs(out_dir, exist_ok=True)
            out_path = os.path.join(out_dir, f"{p}.img")
        extract_partition(hf, data_start, block_size, by_name[p], out_path, a.max_mb)


if __name__ == "__main__":
    main()
