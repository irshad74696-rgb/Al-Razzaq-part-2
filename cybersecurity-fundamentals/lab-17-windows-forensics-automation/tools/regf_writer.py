#!/usr/bin/env python3
"""
Minimal writer for Windows registry hive files (regf format).

Same reason as evtx_writer.py: real hives from a real PC are full of
personal data, so the committed samples are built from scratch in the
real on-disk format:

  base block (4 KiB, "regf")   -> sequence numbers, root cell, XOR checksum
  one hive bin ("hbin")        -> all cells, 8-byte aligned
    nk cells                   -> keys (name, last-write time, parent, lists)
    vk cells + data cells      -> values (REG_SZ, REG_EXPAND_SZ, REG_DWORD, ...)
    lf cells                   -> subkey lists, sorted by upper-case name
    value list cells           -> arrays of vk offsets
  free cell                    -> the unused rest of the bin

Each key's last-write time is set explicitly, because those timestamps
are forensic evidence in their own right (when was this Run key added?).

Standard library only. Values larger than one cell (16 KiB) are not needed
for the samples and are rejected.
"""

import struct
from datetime import datetime, timezone

REG_NONE = 0
REG_SZ = 1
REG_EXPAND_SZ = 2
REG_BINARY = 3
REG_DWORD = 4
REG_MULTI_SZ = 7
REG_QWORD = 11

HBIN_START = 0x1000
NO_CELL = 0xFFFFFFFF


def to_filetime(dt):
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    delta = dt - datetime(1970, 1, 1, tzinfo=timezone.utc)
    ticks = (delta.days * 86400 + delta.seconds) * 10_000_000 + delta.microseconds * 10
    return ticks + 116444736000000000


def encode_data(vtype, value):
    if vtype in (REG_SZ, REG_EXPAND_SZ):
        return (str(value) + "\x00").encode("utf-16-le")
    if vtype == REG_DWORD:
        return struct.pack("<I", int(value) & 0xFFFFFFFF)
    if vtype == REG_QWORD:
        return struct.pack("<Q", int(value) & 0xFFFFFFFFFFFFFFFF)
    if vtype == REG_MULTI_SZ:
        return ("".join(s + "\x00" for s in value) + "\x00").encode("utf-16-le")
    if vtype in (REG_BINARY, REG_NONE):
        return bytes(value)
    raise ValueError("unsupported registry type %d" % vtype)


class Key:
    def __init__(self, name, timestamp, values=None, subkeys=None):
        self.name = name
        self.timestamp = timestamp
        self.values = list(values or [])     # (name, type, value)
        self.subkeys = list(subkeys or [])

    def add(self, path, timestamp, values=None):
        """Create (or reuse) a backslash path below this key, return the leaf."""
        node = self
        for part in path.split("\\"):
            found = next((k for k in node.subkeys if k.name.lower() == part.lower()), None)
            if found is None:
                found = Key(part, timestamp)
                node.subkeys.append(found)
            node = found
        node.timestamp = timestamp
        if values:
            node.values.extend(values)
        return node


class _Bin:
    def __init__(self):
        self.buf = bytearray(b"\0" * 0x20)   # hbin header, filled at the end

    def alloc(self, payload_size):
        """Reserve a cell; returns its offset relative to the first hbin."""
        size = (payload_size + 4 + 7) & ~7
        offset = len(self.buf)
        self.buf += struct.pack("<i", -size) + b"\0" * (size - 4)
        return offset

    def put(self, offset, data):
        """Write payload bytes into an allocated cell."""
        self.buf[offset + 4:offset + 4 + len(data)] = data


def _write_value(hbin, name, vtype, value):
    data = encode_data(vtype, value)
    if len(data) > 16344:
        raise ValueError("value %s too large for this writer" % name)
    name_bytes = name.encode("ascii")
    vk = hbin.alloc(0x14 + len(name_bytes))
    if len(data) <= 4:
        length = 0x80000000 | len(data)
        data_field = data.ljust(4, b"\0")
    else:
        cell = hbin.alloc(len(data))
        hbin.put(cell, data)
        length = len(data)
        data_field = struct.pack("<I", cell)
    record = b"vk" + struct.pack("<HI", len(name_bytes), length) + data_field
    record += struct.pack("<IHH", vtype, 1 if name_bytes else 0, 0) + name_bytes
    hbin.put(vk, record)
    return vk, len(data)


def _write_key(hbin, key, parent_offset, is_root=False):
    name_bytes = key.name.encode("ascii")
    nk = hbin.alloc(0x4C + len(name_bytes))

    value_list = NO_CELL
    max_value_name = max_value_data = 0
    if key.values:
        offsets = []
        for vname, vtype, value in key.values:
            vk, size = _write_value(hbin, vname, vtype, value)
            offsets.append(vk)
            max_value_name = max(max_value_name, len(vname) * 2)
            max_value_data = max(max_value_data, size)
        value_list = hbin.alloc(4 * len(offsets))
        hbin.put(value_list, b"".join(struct.pack("<I", o) for o in offsets))

    subkey_list = NO_CELL
    children = sorted(key.subkeys, key=lambda k: k.name.upper())
    if children:
        child_offsets = [_write_key(hbin, child, nk) for child in children]
        subkey_list = hbin.alloc(4 + 8 * len(children))
        body = b"lf" + struct.pack("<H", len(children))
        for child, offset in zip(children, child_offsets):
            hint = child.name.encode("ascii")[:4].ljust(4, b"\0")
            body += struct.pack("<I", offset) + hint
        hbin.put(subkey_list, body)

    flags = 0x20 | (0x2C if is_root else 0)
    record = b"nk" + struct.pack("<HQI", flags, to_filetime(key.timestamp), 0)
    record += struct.pack(
        "<IIIIIIIIIIIIIIHH",
        parent_offset if not is_root else 0,
        len(children), 0, subkey_list, NO_CELL,
        len(key.values), value_list,
        NO_CELL, NO_CELL,                         # security, class name
        max((len(c.name) * 2 for c in children), default=0), 0,
        max_value_name, max_value_data, 0,
        len(name_bytes), 0,
    )
    record += name_bytes
    hbin.put(nk, record)
    return nk


def write_hive(path, root, hive_path, modified=None):
    """
    Write `root` (a Key tree) to `path`. `hive_path` is the internal file
    name Windows records, e.g. "\\SystemRoot\\System32\\Config\\SYSTEM";
    python-registry uses it to tell the hive type.
    """
    if modified is None:                       # newest key write in the tree
        stack, modified = [root], root.timestamp
        while stack:
            key = stack.pop()
            modified = max(modified, key.timestamp)
            stack.extend(key.subkeys)
    hbin = _Bin()
    root_offset = _write_key(hbin, root, 0, is_root=True)

    # Pad the bin to a 4 KiB multiple with one free cell.
    used = len(hbin.buf)
    total = (used + 8 + 0xFFF) & ~0xFFF
    hbin.buf += struct.pack("<i", total - used) + b"\0" * (total - used - 4)
    hbin.buf[0:0x20] = b"hbin" + struct.pack("<IIQQI", 0, total, 0,
                                             to_filetime(modified), 0)

    base = bytearray(HBIN_START)
    base[0:4] = b"regf"
    struct.pack_into("<IIQIIIIIII", base, 4,
                     1, 1, to_filetime(modified),
                     1, 5, 0, 1,             # version 1.5, primary file, direct memory load
                     root_offset, total, 1)
    # The field holds 64 bytes; Windows keeps the last 31 characters.
    name = hive_path[-31:].encode("utf-16-le")
    base[0x30:0x30 + len(name)] = name
    checksum = 0
    for i in range(0, 0x1FC, 4):
        checksum ^= struct.unpack_from("<I", base, i)[0]
    if checksum == 0:
        checksum = 1
    elif checksum == 0xFFFFFFFF:
        checksum = 0xFFFFFFFE
    struct.pack_into("<I", base, 0x1FC, checksum)

    with open(path, "wb") as fh:
        fh.write(base)
        fh.write(hbin.buf)
