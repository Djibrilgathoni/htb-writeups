#!/usr/bin/env python3
"""
Resolve the full path of an MFT record by walking its parent-record chain.

Usage:
    python3 resolve_path.py mft_output.csv <record_number>
    python3 resolve_path.py mft_output.csv --name "ApbxHelper.exe"
"""
import csv
import sys

def load_records(csv_path):
    records = {}
    with open(csv_path, "r", encoding="utf-8", errors="ignore") as f:
        reader = csv.reader(f)
        header = next(reader)
        for row in reader:
            if len(row) < 7:
                continue
            try:
                rec_num = int(row[0])
                parent_num = int(row[5])
            except ValueError:
                continue
            filename = row[7] if len(row) > 7 else ""
            records[rec_num] = (parent_num, filename)
    return records

def resolve_path(records, rec_num, max_depth=50):
    parts = []
    current = rec_num
    seen = set()
    for _ in range(max_depth):
        if current not in records or current in seen:
            break
        seen.add(current)
        parent_num, filename = records[current]
        parts.append(filename)
        if parent_num == current or parent_num not in records:
            break
        current = parent_num
    parts.reverse()
    parts = [p for p in parts if p and p != "."]
    return "C:\\" + "\\".join(parts)

if __name__ == "__main__":
    if len(sys.argv) < 3:
        print(__doc__)
        sys.exit(1)

    csv_path = sys.argv[1]
    records = load_records(csv_path)

    if sys.argv[2] == "--name":
        target_name = sys.argv[3].lower()
        matches = [rn for rn, (_, fn) in records.items() if fn.lower() == target_name]
        if not matches:
            print(f"No record found for filename: {sys.argv[3]}")
            sys.exit(1)
        for rn in matches:
            print(f"[Record {rn}] {resolve_path(records, rn)}")
    else:
        rec_num = int(sys.argv[2])
        print(resolve_path(records, rec_num))
