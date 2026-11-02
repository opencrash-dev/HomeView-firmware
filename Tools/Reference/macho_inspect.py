"""Read-only, bounded Mach-O and arm64e chained-pointer inspection.

This is a loader research component, not a dyld replacement. It does not
resolve imports, sign pointers, map executable memory, or modify its input.
Format reference: Apple's mach-o/loader.h and mach-o/fixup-chains.h.
"""

import argparse
import hashlib
import json
from pathlib import Path
import struct


class FormatError(ValueError):
    pass


def unpack(data, fmt, offset):
    if offset < 0 or offset + struct.calcsize(fmt) > len(data):
        raise FormatError(f"Out-of-bounds structure at {offset:#x}")
    return struct.unpack_from(fmt, data, offset)


def text(data):
    return data.split(b"\0", 1)[0].decode("utf-8", errors="replace")


def chained_pointer(raw, pointer_format):
    """Decode metadata only. A chain word is NOT a runtime signed pointer."""
    if pointer_format not in (1, 9, 12):
        raise FormatError(f"Unsupported chained pointer format {pointer_format}")
    if not 0 <= raw < 1 << 64:
        raise FormatError("Chain word must be an unsigned 64-bit value")
    auth, bind = bool(raw >> 63), bool((raw >> 62) & 1)
    result = dict(authenticated=auth, bind=bind, next_bytes=((raw >> 51) & 0x7ff) * 8)
    if bind:
        ordinal_bits = 24 if pointer_format == 12 else 16
        result["ordinal"] = raw & ((1 << ordinal_bits) - 1)
        if (raw >> ordinal_bits) & ((1 << (32 - ordinal_bits)) - 1):
            raise FormatError("Nonzero reserved bind bits")
    if auth:
        result.update(diversity=(raw >> 32) & 0xffff,
                      address_diversity=bool((raw >> 48) & 1),
                      key=("IA", "IB", "DA", "DB")[(raw >> 49) & 3])
        if not bind:
            result["target_image_offset"] = raw & 0xffffffff
    elif bind:
        addend = (raw >> 32) & 0x7ffff
        result["addend"] = addend - (1 << 19) if addend & (1 << 18) else addend
    else:
        result["target_low43"] = raw & ((1 << 43) - 1)
        result["high8"] = (raw >> 43) & 0xff
        result["target_kind"] = "vm_address" if pointer_format == 1 else "image_offset"
    return result


def inspect(data, header_offset=0, include_fixups=True, limit=200000):
    magic, cpu, subtype, kind, count, length, flags, reserved = unpack(data, "<8I", header_offset)
    if magic != 0xfeedfacf or cpu != 0x100000c:
        raise FormatError("Expected thin little-endian AArch64 Mach-O")
    cursor = header_offset + 32
    end = cursor + length
    if end > len(data) or count > length // 8:
        raise FormatError("Invalid Mach-O command region")
    segments, entries, chains, versions = [], [], [], []
    entry = None
    for _ in range(count):
        command, size = unpack(data, "<II", cursor)
        if size < 8 or size % 8 or cursor + size > end:
            raise FormatError("Invalid load command size")
        if command == 0x19:  # LC_SEGMENT_64
            if size < 72:
                raise FormatError("Truncated segment command")
            name, vm, vm_size, off, file_size, maximum, initial, sections, seg_flags = unpack(
                data, "<16sQQQQIIII", cursor + 8)
            if size != 72 + sections * 80 or off + file_size > len(data) or file_size > vm_size:
                raise FormatError("Invalid segment range or sections")
            segments.append(dict(name=text(name), vm_address=vm, vm_size=vm_size,
                                 file_offset=off, file_size=file_size, protection=initial))
        elif command == 0x80000035:  # LC_FILESET_ENTRY
            if size < 32:
                raise FormatError("Truncated fileset entry")
            vm, off, string, _ = unpack(data, "<QQII", cursor + 8)
            if off + 32 > len(data) or not 32 <= string < size:
                raise FormatError("Invalid fileset entry")
            name_bytes = data[cursor + string:cursor + size]
            if b"\0" not in name_bytes:
                raise FormatError("Unterminated fileset identifier")
            entries.append(dict(name=text(name_bytes), vm_address=vm, file_offset=off))
        elif command == 0x80000034:  # LC_DYLD_CHAINED_FIXUPS
            if size != 16:
                raise FormatError("Invalid chained-fixup command")
            off, size_bytes = unpack(data, "<II", cursor + 8)
            if off + size_bytes > len(data):
                raise FormatError("Chained-fixup blob outside file")
            chains.append((off, size_bytes))
        elif command == 0x32:  # LC_BUILD_VERSION
            if size < 24:
                raise FormatError("Truncated build version")
            plat, minimum, sdk, tools = unpack(data, "<4I", cursor + 8)
            if size != 24 + tools * 8:
                raise FormatError("Invalid build-tool array")
            def version(value):
                return f"{value >> 16}.{(value >> 8) & 255}.{value & 255}"
            versions.append(dict(platform=plat, minimum=version(minimum), sdk=version(sdk)))
        elif command == 5:  # LC_UNIXTHREAD; fixture/original ARM_THREAD_STATE64
            if size == 288 and unpack(data, "<II", cursor + 8) == (6, 68):
                entry = unpack(data, "<Q", cursor + 16 + 32 * 8)[0]
        cursor += size
    if cursor != end:
        raise FormatError("Load commands do not fill declared region")
    if len(chains) > 1:
        raise FormatError("Multiple chained-fixup commands")
    result = dict(cpu_type=cpu, cpu_subtype=subtype, arm64e=(subtype & 0xffffff) == 2,
                  file_type=kind, segments=segments, fileset_entries=entries,
                  build_versions=versions, unixthread_entry=entry)
    result["unixthread_entry_in_executable_segment"] = (None if entry is None else any(
        s["protection"] & 4 and s["vm_address"] <= entry < s["vm_address"] + s["vm_size"]
        for s in segments))
    if include_fixups and chains:
        off, length = chains[0]
        result["chained_fixups"] = walk_chains(data, data[off:off + length], segments, limit)
    return result


def walk_chains(image, blob, segments, limit):
    version, starts, imports, symbols, import_count, import_format, symbol_format = unpack(blob, "<7I", 0)
    if version != 0 or starts < 28 or imports > len(blob) or symbols > len(blob):
        raise FormatError("Unsupported or invalid fixup header")
    if import_format not in (1, 2, 3) or symbol_format != 0:
        raise FormatError("Unsupported import/symbol format")
    if imports + import_count * {1: 4, 2: 8, 3: 16}[import_format] > len(blob):
        raise FormatError("Truncated import table")
    count, = unpack(blob, "<I", starts)
    if count > len(segments) or starts + 4 + count * 4 > len(blob):
        raise FormatError("Invalid chain segment table")
    bases = [s["vm_address"] for s in segments if s["file_offset"] == 0 and s["file_size"]]
    if not bases:
        raise FormatError("Image base not found")
    base = min(bases)
    records, formats = [], set()
    for index in range(count):
        relative, = unpack(blob, "<I", starts + 4 + index * 4)
        if not relative:
            continue
        pos = starts + relative
        size, page_size, fmt, segment_offset, _, page_count = unpack(blob, "<IHHQIH", pos)
        if size < 22 + page_count * 2 or pos + size > len(blob) or page_size not in (4096, 16384):
            raise FormatError("Invalid chain segment metadata")
        if fmt not in (1, 9, 12):
            raise FormatError(f"Unsupported chained pointer format {fmt}")
        formats.add(fmt)
        segment = segments[index]
        if base + segment_offset != segment["vm_address"]:
            raise FormatError("Chained segment VM offset mismatch")
        if page_count > (segment["vm_size"] + page_size - 1) // page_size:
            raise FormatError("Chain page table exceeds segment")
        for page in range(page_count):
            first, = unpack(blob, "<H", pos + 22 + page * 2)
            if first == 0xffff:
                continue
            if first & 0x8000:
                raise FormatError("Multi-start pages are not implemented")
            location = first
            while True:
                delta = page * page_size + location
                if location + 8 > page_size or delta + 8 > segment["file_size"] or location % 8:
                    raise FormatError("Chained pointer outside file-backed page or misaligned")
                file_offset = segment["file_offset"] + delta
                raw, = unpack(image, "<Q", file_offset)
                pointer = chained_pointer(raw, fmt)
                if pointer.get("ordinal", -1) >= import_count:
                    raise FormatError("Bind ordinal outside imports table")
                if len(records) >= limit:
                    raise FormatError("Fixup record limit exceeded")
                records.append(dict(file_offset=file_offset,
                                    storage_vm_address=segment["vm_address"] + delta,
                                    pointer_format=fmt, **pointer))
                if not pointer["next_bytes"]:
                    break
                location += pointer["next_bytes"]
    return dict(pointer_formats=sorted(formats), imports_count=import_count,
                records=records, count=len(records),
                limitation="Metadata only; imports unresolved and pointers not signed")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("image", type=Path)
    parser.add_argument("--out", type=Path)
    parser.add_argument("--headers-only", action="store_true",
                        help="Do not walk userland chains (e.g. for kernel filesets)")
    args = parser.parse_args()
    try:
        with args.image.open("rb") as stream:
            data = stream.read(256 * 1024 * 1024 + 1)
        if len(data) > 256 * 1024 * 1024:
            raise FormatError("Input exceeds 256 MiB inspection limit")
        result = inspect(data, include_fixups=not args.headers_only)
        # Fileset inner file offsets refer to the outer container.
        result["inner_images"] = [dict(name=e["name"], **inspect(data, e["file_offset"], False))
                                  for e in result["fileset_entries"]]
        result.update(path=str(args.image), sha256=hashlib.sha256(data).hexdigest(),
                      executable_loaded=False)
    except (OSError, ValueError) as error:
        parser.exit(1, f"Inspection failed: {error}\n")
    output = json.dumps(result, indent=2) + "\n"
    if args.out:
        args.out.write_text(output)
        print(f"Report: {args.out}")
    else:
        print(output, end="")


if __name__ == "__main__":
    main()
