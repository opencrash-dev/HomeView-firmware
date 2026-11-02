"""Inventory adjacent MOV-immediate/SVC stubs in the original cache.

This intentionally narrow static analysis does not infer runtime reachability,
argument layouts, Mach messages, or complete kernel/userland compatibility.
"""

import argparse
import hashlib
import json
from pathlib import Path
import re
import struct


def immediate_x16(words):
    """Resolve a contiguous MOVZ/MOVN followed by MOVK sequence for X16."""
    patches = []
    for word in reversed(words[-4:]):
        opcode = word & 0xff80001f
        shift = ((word >> 21) & 3) * 16
        value = (word >> 5) & 0xffff
        if opcode == 0xf2800010:  # MOVK X16
            patches.append((shift, value))
            continue
        if opcode not in (0xd2800010, 0x92800010):
            return None
        result = value << shift
        if opcode == 0x92800010:  # MOVN X16
            result ^= (1 << 64) - 1
        for patch_shift, patch_value in reversed(patches):
            mask = 0xffff << patch_shift
            result = (result & ~mask) | (patch_value << patch_shift)
        return result - (1 << 64) if result >> 63 else result
    return None


def scan_stubs(code, address):
    if len(code) % 4:
        raise ValueError("Unaligned A64 instruction section")
    words = [w[0] for w in struct.iter_unpack("<I", code)]
    result = []
    for index, word in enumerate(words):
        if word != 0xd4001001:  # SVC #0x80, Darwin's trap immediate
            continue
        number = immediate_x16(words[max(0, index - 4):index])
        if number is None:
            kind = "unresolved"
        elif number == 0:
            kind = "indirect_bsd_dispatch"
        elif number == 0x80000000:
            kind = "platform"
        elif number < 0:
            kind = "mach_or_platform"
        else:
            kind = "bsd_candidate"
        result.append(dict(svc_address=address + index * 4, number=number, kind=kind))
    return result


def source_calls(source):
    """Keep conditional alternatives; no preprocessor configuration is assumed."""
    result = {}
    for line in source.splitlines():
        match = re.match(r"\s*(\d+)\s+\S+\s+\S+\s+\{([^}]+)\}", line)
        if not match:
            continue
        name = re.search(r"\b([A-Za-z_]\w*)\s*\(", match[2])
        if name:
            result.setdefault(int(match[1]), set()).add(name[1])
    return result


def cached_text(cache_dir, index):
    image = next(x for x in index["images"] if x["path"] == "/usr/lib/system/libsystem_kernel.dylib")
    name = image["chunk"]
    if Path(name).name != name:
        raise ValueError("Cache filename must be a basename")
    offset = image["file_offset"]
    with (cache_dir / name).open("rb") as stream:
        stream.seek(offset)
        header = stream.read(32)
        if len(header) != 32:
            raise ValueError("Truncated cached Mach-O header")
        magic, cpu, subtype, kind, count, length, _, _ = struct.unpack("<8I", header)
        if magic != 0xfeedfacf or cpu != 0x100000c or length > 1024 * 1024:
            raise ValueError("Unsupported cached Mach-O")
        commands = stream.read(length)
        if len(commands) != length or count > length // 8:
            raise ValueError("Truncated cached load commands")
        cursor = 0
        found = None
        for _ in range(count):
            if cursor + 8 > length:
                raise ValueError("Command header outside cached image")
            command, size = struct.unpack_from("<II", commands, cursor)
            if size < 8 or cursor + size > length or size % 8:
                raise ValueError("Invalid cached load command")
            if command == 0x19:
                if size < 72:
                    raise ValueError("Truncated cached segment")
                name_bytes, vm, vm_size, _, file_size, _, _, sections, _ = struct.unpack_from(
                    "<16sQQQQIIII", commands, cursor + 8)
                if size != 72 + sections * 80:
                    raise ValueError("Invalid cached section table")
                if name_bytes.rstrip(b"\0") == b"__TEXT":
                    if vm != int(image["address"], 16) or vm_size > 16 * 1024 * 1024:
                        raise ValueError("Cached text does not match supplied index")
                    for section in range(sections):
                        pos = cursor + 72 + section * 80
                        section_name, segment_name, addr, size_bytes = struct.unpack_from("<16s16sQQ", commands, pos)
                        if section_name.rstrip(b"\0") == b"__text":
                            if addr < vm or addr + size_bytes > vm + min(vm_size, file_size):
                                raise ValueError("Code outside contiguous cached text")
                            if found is not None or size_bytes > 16 * 1024 * 1024:
                                raise ValueError("Ambiguous or excessive cached text")
                            found = (addr, offset + addr - vm, size_bytes)
            cursor += size
        if cursor != length or found is None:
            raise ValueError("Cached code section not found")
        address, position, size_bytes = found
        stream.seek(position)
        code = stream.read(size_bytes)
        if len(code) != size_bytes:
            raise ValueError("Truncated cached instructions")
    return code, address, dict(cache_file=name, image_file_offset=offset, cpu_subtype=hex(subtype),
                               text_sha256=hashlib.sha256(code).hexdigest(), text_size=len(code))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--cache-dir", required=True, type=Path)
    parser.add_argument("--cache-index", required=True, type=Path)
    parser.add_argument("--syscalls-master", required=True, type=Path)
    parser.add_argument("--out", required=True, type=Path)
    args = parser.parse_args()
    try:
        code, address, identity = cached_text(args.cache_dir, json.loads(args.cache_index.read_text()))
        raw_source = args.syscalls_master.read_bytes()
        source = source_calls(raw_source.decode())
        stubs = scan_stubs(code, address)
        numbers = sorted({r["number"] for r in stubs if r["kind"] == "bsd_candidate"})
        missing = [dict(number=n, source_alternatives=sorted(source.get(n, set()))) for n in numbers
                   if not source.get(n, set()) - {"nosys", "enosys"}]
        result = dict(identity=identity, syscalls_master_sha256=hashlib.sha256(raw_source).hexdigest(),
                      svc_stubs=stubs, bsd_candidate_numbers=numbers,
                      missing_or_reserved_in_source=missing,
                      unresolved_count=sum(r["number"] is None for r in stubs),
                      limitation="Static adjacent-immediate candidates only; conditional source alternatives retained; no runtime compatibility proof")
        args.out.write_text(json.dumps(result, indent=2) + "\n")
        print(f"SVC sites: {len(stubs)}; BSD candidates: {len(numbers)}; missing/reserved: {len(missing)}")
        print(f"Report: {args.out}")
    except (OSError, ValueError, KeyError, StopIteration) as error:
        parser.exit(1, f"ABI audit failed: {error}\n")


if __name__ == "__main__":
    main()
