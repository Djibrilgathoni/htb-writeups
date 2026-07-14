#!/usr/bin/env python3
import struct
import sys
from datetime import datetime, timedelta

REASON_FLAGS = {
    0x00000001: "DATA_OVERWRITE", 0x00000002: "DATA_EXTEND",
    0x00000004: "DATA_TRUNCATION", 0x00000010: "NAMED_DATA_OVERWRITE",
    0x00000020: "NAMED_DATA_EXTEND", 0x00000040: "NAMED_DATA_TRUNCATION",
    0x00000100: "FILE_CREATE", 0x00000200: "FILE_DELETE",
    0x00000400: "EA_CHANGE", 0x00000800: "SECURITY_CHANGE",
    0x00001000: "RENAME_OLD_NAME", 0x00002000: "RENAME_NEW_NAME",
    0x00004000: "INDEXABLE_CHANGE", 0x00008000: "BASIC_INFO_CHANGE",
    0x00010000: "HARD_LINK_CHANGE", 0x00020000: "COMPRESSION_CHANGE",
    0x00040000: "ENCRYPTION_CHANGE", 0x00080000: "OBJECT_ID_CHANGE",
    0x00100000: "REPARSE_POINT_CHANGE", 0x00200000: "STREAM_CHANGE",
    0x00400000: "TRANSACTED_CHANGE", 0x80000000: "CLOSE",
}

def decode_reason(reason):
    flags = [name for bit, name in REASON_FLAGS.items() if reason & bit]
    return "|".join(flags) if flags else hex(reason)

def filetime_to_dt(ft):
    if ft == 0:
        return None
    try:
        return datetime(1601, 1, 1) + timedelta(microseconds=ft / 10)
    except OverflowError:
        return None

def parse_usn_journal(path, name_filter=None):
    results = []
    with open(path, "rb") as f:
        data = f.read()
    size = len(data)
    offset = 0
    while offset < size - 60:
        record_length = struct.unpack_from("<I", data, offset)[0]
        if record_length == 0 or record_length < 60 or offset + record_length > size:
            offset += 8
            continue
        major_version = struct.unpack_from("<H", data, offset + 4)[0]
        if major_version != 2:
            offset += 8
            continue
        try:
            usn = struct.unpack_from("<q", data, offset + 24)[0]
            timestamp = struct.unpack_from("<q", data, offset + 32)[0]
            reason = struct.unpack_from("<I", data, offset + 40)[0]
            fn_len = struct.unpack_from("<H", data, offset + 56)[0]
            fn_off = struct.unpack_from("<H", data, offset + 58)[0]
            if fn_off < 60 or offset + fn_off + fn_len > size:
                offset += 8
                continue
            filename = data[offset+fn_off: offset+fn_off+fn_len].decode("utf-16-le", errors="ignore")
        except struct.error:
            offset += 8
            continue

        if not name_filter or name_filter.lower() in filename.lower():
            dt = filetime_to_dt(timestamp)
            results.append((dt, usn, decode_reason(reason), filename))

        offset += record_length
    return results

if __name__ == "__main__":
    path = sys.argv[1]
    name_filter = sys.argv[2] if len(sys.argv) > 2 else None
    for dt, usn, reason, filename in parse_usn_journal(path, name_filter):
        print(f"{dt}\t{usn}\t{reason}\t{filename}")
