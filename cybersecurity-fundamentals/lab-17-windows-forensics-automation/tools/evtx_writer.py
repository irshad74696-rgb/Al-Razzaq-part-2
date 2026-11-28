#!/usr/bin/env python3
"""
Minimal writer for Windows XML Event Log (.evtx) files.

Why this exists: the lab machine ships sample .evtx files, but I can't
commit real Windows logs (they hold real account names, SIDs and
addresses), and a parser you never feed a file is a parser you never
tested. So this writes small, synthetic logs in the real on-disk format:

  file header (4 KiB, "ElfFile")  -> CRC32 over the first 0x78 bytes
  chunks of 64 KiB ("ElfChnk")    -> header CRC + data CRC
    string table (64 buckets)     -> element/attribute names, stored once
    template table (32 buckets)   -> one template per event "shape"
    records ("**\0\0")            -> template instance + substitution values

Each record is Binary XML: a template (the XML skeleton with numbered
holes) defined once per chunk, then reused by every later record of the
same shape, which only carries the values. That is how Windows writes
them too, and it is what python-evtx expects to find.

Only the subset of Binary XML that event logs actually use is written.
Standard library only.
"""

import binascii
import struct
import uuid
from datetime import datetime, timezone

CHUNK_SIZE = 0x10000
CHUNK_HEADER_SIZE = 0x200
FILE_HEADER_SIZE = 0x1000

# Binary XML tokens
T_END_OF_STREAM = 0x00
T_OPEN_START = 0x01
T_CLOSE_START = 0x02
T_CLOSE_EMPTY = 0x03
T_END_ELEMENT = 0x04
T_VALUE = 0x05
T_ATTRIBUTE = 0x06
T_TEMPLATE_INSTANCE = 0x0C
T_NORMAL_SUB = 0x0D
T_OPTIONAL_SUB = 0x0E
T_START_OF_STREAM = 0x0F
FLAG_MORE = 0x40  # "has attributes" on an element, "more follow" on an attribute

# Value types
V_NULL = 0x00
V_WSTRING = 0x01
V_UINT8 = 0x04
V_UINT16 = 0x06
V_UINT32 = 0x08
V_UINT64 = 0x0A
V_FILETIME = 0x11
V_HEX64 = 0x15

EVENT_NS = "http://schemas.microsoft.com/win/2004/08/events/event"
FILETIME_EPOCH_OFFSET = 116444736000000000


def to_filetime(dt):
    """datetime (aware or naive UTC) -> 100 ns ticks since 1601-01-01."""
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    delta = dt - datetime(1970, 1, 1, tzinfo=timezone.utc)
    ticks = (delta.days * 86400 + delta.seconds) * 10_000_000 + delta.microseconds * 10
    return ticks + FILETIME_EPOCH_OFFSET


def name_hash(name):
    """16-bit name hash used for the chunk string table."""
    value = 0
    for ch in name:
        value = (value * 65599 + ord(ch)) & 0xFFFFFFFF
    return value & 0xFFFF


def encode_value(vtype, value):
    """Encode one substitution value. Returns raw bytes."""
    if vtype == V_NULL or value is None:
        return b""
    if vtype == V_WSTRING:
        return (str(value) + "\x00").encode("utf-16-le")
    if vtype == V_UINT8:
        return struct.pack("<B", int(value))
    if vtype == V_UINT16:
        return struct.pack("<H", int(value))
    if vtype == V_UINT32:
        return struct.pack("<I", int(value))
    if vtype in (V_UINT64, V_HEX64):
        return struct.pack("<Q", int(value))
    if vtype == V_FILETIME:
        return struct.pack("<Q", to_filetime(value))
    raise ValueError("unsupported value type 0x%02x" % vtype)


class Event:
    """
    One event. `data` is an ordered list of (name, value) pairs.

    kind="EventData": <EventData><Data Name="...">value</Data>...</EventData>
    kind="UserData":  <UserData><{wrapper}><{name}>value</{name}>...</{wrapper}></UserData>
    """

    def __init__(self, event_id, timestamp, provider, provider_guid, channel,
                 computer, data=(), level=0, task=0, opcode=0, version=0,
                 keywords=0x8020000000000000, process_id=4, thread_id=8,
                 user_sid=None, kind="EventData", wrapper=None,
                 event_source_name=None):
        self.event_id = event_id
        self.timestamp = timestamp
        self.provider = provider
        self.provider_guid = provider_guid
        self.channel = channel
        self.computer = computer
        self.data = list(data)
        self.level = level
        self.task = task
        self.opcode = opcode
        self.version = version
        self.keywords = keywords
        self.process_id = process_id
        self.thread_id = thread_id
        self.user_sid = user_sid
        self.kind = kind
        self.wrapper = wrapper
        self.event_source_name = event_source_name

    def shape(self):
        """Events with the same shape share one template."""
        return (
            self.kind,
            self.wrapper,
            tuple(name for name, _ in self.data),
            self.user_sid is not None,
            self.event_source_name is not None,
        )

    def substitutions(self, record_id):
        """Values in template-hole order: list of (type, value)."""
        subs = [
            (V_WSTRING, self.provider),
            (V_WSTRING, self.provider_guid),
        ]
        if self.event_source_name is not None:
            subs.append((V_WSTRING, self.event_source_name))
        subs += [
            (V_UINT16, self.event_id),
            (V_UINT8, self.version),
            (V_UINT8, self.level),
            (V_UINT16, self.task),
            (V_UINT8, self.opcode),
            (V_HEX64, self.keywords),
            (V_FILETIME, self.timestamp),
            (V_UINT64, record_id),
            (V_UINT32, self.process_id),
            (V_UINT32, self.thread_id),
            (V_WSTRING, self.channel),
            (V_WSTRING, self.computer),
        ]
        if self.user_sid is not None:
            subs.append((V_WSTRING, self.user_sid))
        for _, value in self.data:
            if isinstance(value, int) and not isinstance(value, bool):
                subs.append((V_UINT32, value))
            else:
                subs.append((V_WSTRING, "" if value is None else value))
        return subs

    def template_types(self, record_id=1):
        return [t for t, _ in self.substitutions(record_id)]


class _Chunk:
    """Builds one 64 KiB chunk."""

    def __init__(self, first_record_number):
        self.data = bytearray()          # everything after the 0x200 header
        self.strings = {}                # name -> chunk offset
        self.string_buckets = [0] * 64
        self.templates = {}              # (shape, types) -> (offset, id)
        self.template_buckets = [0] * 32
        self.first_record = first_record_number
        self.last_record = first_record_number - 1
        self.last_record_offset = 0

    def snapshot(self):
        return (len(self.data), dict(self.strings), list(self.string_buckets),
                dict(self.templates), list(self.template_buckets))

    def restore(self, snap):
        size, strings, sbuckets, templates, tbuckets = snap
        del self.data[size:]
        self.strings, self.string_buckets = strings, sbuckets
        self.templates, self.template_buckets = templates, tbuckets

    def pos(self, buf):
        """Chunk-relative offset of the next byte appended to buf."""
        return CHUNK_HEADER_SIZE + len(self.data) + len(buf)

    # ---- names -------------------------------------------------------
    def name_ref(self, buf, name, field_at):
        """
        Write a name reference. `field_at` is the index in buf of the
        4-byte offset field (already reserved). If the name is new in this
        chunk, the NameString is written inline right here.
        """
        if name in self.strings:
            struct.pack_into("<I", buf, field_at, self.strings[name])
            return
        offset = self.pos(buf)
        bucket = name_hash(name) % 64
        buf += struct.pack("<IHH", self.string_buckets[bucket], name_hash(name), len(name))
        buf += name.encode("utf-16-le") + b"\x00\x00"
        self.string_buckets[bucket] = offset
        self.strings[name] = offset
        struct.pack_into("<I", buf, field_at, offset)

    # ---- elements ----------------------------------------------------
    def element(self, buf, name, attrs=(), content=None, children=()):
        """
        attrs: list of (name, ('value', text) | ('sub', index, type, optional))
        content: ('sub', index, type, optional) or None
        children: list of callables(buf) writing child elements
        """
        start = len(buf)
        buf.append(T_OPEN_START | (FLAG_MORE if attrs else 0))
        buf += struct.pack("<H", 0xFFFF)          # dependency id: none
        size_at = len(buf)
        buf += b"\0\0\0\0"                        # data size, patched below
        name_at = len(buf)
        buf += b"\0\0\0\0"
        self.name_ref(buf, name, name_at)
        if attrs:
            attr_size_at = len(buf)
            buf += b"\0\0\0\0"
            attr_start = len(buf)
            for i, (aname, avalue) in enumerate(attrs):
                more = i < len(attrs) - 1
                buf.append(T_ATTRIBUTE | (FLAG_MORE if more else 0))
                field = len(buf)
                buf += b"\0\0\0\0"
                self.name_ref(buf, aname, field)
                self._value_or_sub(buf, avalue)
            struct.pack_into("<I", buf, attr_size_at, len(buf) - attr_start)
        if content is None and not children:
            buf.append(T_CLOSE_EMPTY)
        else:
            buf.append(T_CLOSE_START)
            if content is not None:
                self._value_or_sub(buf, content)
            for child in children:
                child(buf)
            buf.append(T_END_ELEMENT)
        struct.pack_into("<I", buf, size_at, len(buf) - size_at - 4)
        return start

    @staticmethod
    def _value_or_sub(buf, spec):
        if spec[0] == "value":
            text = spec[1]
            buf += struct.pack("<BBH", T_VALUE, V_WSTRING, len(text))
            buf += text.encode("utf-16-le")
        else:
            _, index, vtype, optional = spec
            token = T_OPTIONAL_SUB if optional else T_NORMAL_SUB
            buf += struct.pack("<BHB", token, index, vtype)

    # ---- templates ---------------------------------------------------
    def template_body(self, buf, event, types):
        """The <Event> skeleton with numbered substitution holes."""
        counter = iter(range(len(types)))

        def sub(optional=False):
            i = next(counter)
            return ("sub", i, types[i], optional)

        provider_attrs = [("Name", sub()), ("Guid", sub())]
        if event.event_source_name is not None:
            provider_attrs.append(("EventSourceName", sub()))
        # Build System children in document order; each closure captures
        # its substitution index now, so the numbering matches substitutions().
        s_event_id, s_version, s_level, s_task, s_opcode, s_keywords = (
            sub(), sub(), sub(), sub(), sub(), sub())
        s_time, s_record = sub(), sub()
        s_pid, s_tid = sub(), sub()
        s_channel, s_computer = sub(), sub()
        s_user = sub() if event.user_sid is not None else None
        data_subs = [(name, sub(optional=True)) for name, _ in event.data]

        system_children = [
            lambda b: self.element(b, "Provider", attrs=provider_attrs),
            lambda b: self.element(b, "EventID", content=s_event_id),
            lambda b: self.element(b, "Version", content=s_version),
            lambda b: self.element(b, "Level", content=s_level),
            lambda b: self.element(b, "Task", content=s_task),
            lambda b: self.element(b, "Opcode", content=s_opcode),
            lambda b: self.element(b, "Keywords", content=s_keywords),
            lambda b: self.element(b, "TimeCreated", attrs=[("SystemTime", s_time)]),
            lambda b: self.element(b, "EventRecordID", content=s_record),
            lambda b: self.element(b, "Correlation"),
            lambda b: self.element(b, "Execution", attrs=[("ProcessID", s_pid), ("ThreadID", s_tid)]),
            lambda b: self.element(b, "Channel", content=s_channel),
            lambda b: self.element(b, "Computer", content=s_computer),
            (lambda b: self.element(b, "Security", attrs=[("UserID", s_user)]))
            if s_user else (lambda b: self.element(b, "Security")),
        ]

        if event.kind == "UserData":
            inner = [
                (lambda b, n=n, s=s: self.element(b, n, content=s)) for n, s in data_subs
            ]
            payload = lambda b: self.element(  # noqa: E731
                b, "UserData",
                children=[lambda b2: self.element(b2, event.wrapper, children=inner)])
        else:
            datas = [
                (lambda b, n=n, s=s: self.element(
                    b, "Data", attrs=[("Name", ("value", n))], content=s))
                for n, s in data_subs
            ]
            payload = lambda b: self.element(b, "EventData", children=datas)  # noqa: E731

        buf += bytes([T_START_OF_STREAM, 1, 1, 0])
        self.element(
            buf, "Event",
            attrs=[("xmlns", ("value", EVENT_NS))],
            children=[lambda b: self.element(b, "System", children=system_children), payload],
        )
        buf.append(T_END_OF_STREAM)

    # ---- records -----------------------------------------------------
    def add_record(self, event, record_number):
        """Append one record. Returns False (and changes nothing) if full."""
        snap = self.snapshot()
        subs = event.substitutions(record_number)
        types = [t for t, _ in subs]
        key = (event.shape(), tuple(types))

        rec = bytearray()
        rec += struct.pack("<IIQQ", 0x00002A2A, 0, record_number, to_filetime(event.timestamp))
        rec += bytes([T_START_OF_STREAM, 1, 1, 0])
        if key in self.templates:
            t_offset, t_id = self.templates[key]
            rec += struct.pack("<BBII", T_TEMPLATE_INSTANCE, 1, t_id, t_offset)
        else:
            guid = uuid.uuid5(uuid.NAMESPACE_URL, "evtx-template:%r" % (key,)).bytes_le
            t_id = struct.unpack("<I", guid[:4])[0]
            t_offset = self.pos(rec) + 10
            rec += struct.pack("<BBII", T_TEMPLATE_INSTANCE, 1, t_id, t_offset)
            header_at = len(rec)
            bucket = len(self.templates) % 32
            rec += struct.pack("<I", self.template_buckets[bucket]) + guid + b"\0\0\0\0"
            body_start = len(rec)
            self.template_body(rec, event, types)
            struct.pack_into("<I", rec, header_at + 20, len(rec) - body_start)
            self.template_buckets[bucket] = t_offset
            self.templates[key] = (t_offset, t_id)

        values = [encode_value(t, v) for t, v in subs]
        rec += struct.pack("<I", len(subs))
        for (vtype, _), raw in zip(subs, values):
            rec += struct.pack("<HBB", len(raw), vtype if raw else V_NULL, 0)
        for raw in values:
            rec += raw
        rec += b"\0\0\0\0"                      # trailing size copy
        while len(rec) % 8:                      # keep records 8-byte aligned
            rec.insert(len(rec) - 4, 0)
        struct.pack_into("<I", rec, 4, len(rec))
        struct.pack_into("<I", rec, len(rec) - 4, len(rec))

        if CHUNK_HEADER_SIZE + len(self.data) + len(rec) > CHUNK_SIZE:
            self.restore(snap)
            return False
        self.last_record_offset = CHUNK_HEADER_SIZE + len(self.data)
        self.data += rec
        self.last_record = record_number
        return True

    def to_bytes(self):
        body = bytes(self.data)
        free = CHUNK_HEADER_SIZE + len(body)
        header = bytearray(CHUNK_HEADER_SIZE)
        header[0:8] = b"ElfChnk\x00"
        struct.pack_into("<QQQQIII", header, 8,
                         self.first_record, self.last_record,
                         self.first_record, self.last_record,
                         0x80, self.last_record_offset, free)
        struct.pack_into("<I", header, 0x34, binascii.crc32(body) & 0xFFFFFFFF)
        for i, off in enumerate(self.string_buckets):
            struct.pack_into("<I", header, 0x80 + 4 * i, off)
        for i, off in enumerate(self.template_buckets):
            struct.pack_into("<I", header, 0x180 + 4 * i, off)
        crc = binascii.crc32(bytes(header[0:0x78]) + bytes(header[0x80:0x200])) & 0xFFFFFFFF
        struct.pack_into("<I", header, 0x7C, crc)
        return bytes(header) + body + b"\0" * (CHUNK_SIZE - free)


def write_evtx(path, events):
    """Write events (in the given order) to an .evtx file. Returns record count."""
    chunks = []
    record_number = 1
    current = None
    for event in events:
        if current is None or not current.add_record(event, record_number):
            current = _Chunk(record_number)
            chunks.append(current)
            if not current.add_record(event, record_number):
                raise ValueError("event %d is too large for one chunk" % event.event_id)
        record_number += 1

    header = bytearray(FILE_HEADER_SIZE)
    header[0:8] = b"ElfFile\x00"
    struct.pack_into("<QQQIHHHH", header, 8,
                     0, max(len(chunks) - 1, 0), record_number,
                     0x80, 1, 3, 0x1000, len(chunks))
    struct.pack_into("<I", header, 0x78, 0)    # flags: clean, not full
    struct.pack_into("<I", header, 0x7C, binascii.crc32(bytes(header[:0x78])) & 0xFFFFFFFF)

    with open(path, "wb") as fh:
        fh.write(header)
        for chunk in chunks:
            fh.write(chunk.to_bytes())
    return record_number - 1
