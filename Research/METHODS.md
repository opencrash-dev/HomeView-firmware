# Methods and Validation

Recorded on 2026-11-01. This describes work actually performed, not a complete system-port recipe. The early-stage sections are followed by links to the subsequent userland and complete-expansion records.

## Local environment

- macOS 27.0.1, build `26A434`, arm64.
- Xcode selected at `/Applications/Xcode.app/Contents/Developer`.
- Swift compiler reports Apple Swift 6.4, `swiftlang-6.4.0.34.1`.
- `/usr/bin/aa`, `file`, `shasum`, Python 3, and the system Compression library were available.
- `ipsw` was not found in PATH. No dependency was installed.
- A memory-size query was denied in the restricted environment; available RAM was not established.
- Free space varied from approximately 32 GiB to 20 GiB, and later 25 GiB. These are snapshots, not storage requirements. No cleanup was performed by this work.

## Initial checks

Run from the project root:

```sh
stat -f '%z bytes' 91e6292d137569817d83050e9a21c6c93c25af6ab02fbaa7eeddb9ad5439b99a.aea
xxd -l 128 91e6292d137569817d83050e9a21c6c93c25af6ab02fbaa7eeddb9ad5439b99a.aea
shasum -a 256 91e6292d137569817d83050e9a21c6c93c25af6ab02fbaa7eeddb9ad5439b99a.aea
```

The hash, size, and magic are recorded in [Firmware findings](FIRMWARE_FINDINGS.md). The sample was only opened for reading. After metadata/kernel extraction and documentation, SHA-256 was recomputed and remained `03b7b44bbe09fa033cd35077d8e5c3455b227d86ce7a528ecc6ef2165635f570`.

## Why ordinary extraction did not work

`aa list` without verbosity returned no visible listing. `aa list -v` displayed the nested layout. Selective `aa extract` attempts using both regex and path filters completed but extracted zero regular files.

The outer archive contains metadata records with `YOP=E`; their `DAT` blobs are nested Apple Archives containing regular files. The observed ordinary extraction did not descend into those records. Do not interpret an exit status of zero as proof that selected files were written.

This structure is also described in the pinned [VPhoneOTAArchive implementation](https://github.com/Lakr233/vphone-cli/blob/57bbc93c5a3498919f2cea0ed0be60d83e28055b/VPhoneKit/VPhoneArchiveKit/Transfer/VPhoneOTAArchive.swift).

## Bounded streaming extraction

A temporary Swift helper used the system AppleArchive, CryptoKit, Foundation, and System modules. Its segment adapter was adapted from the pinned vphone implementation, with its MIT notice retained. No vphone application, package graph, or runtime was built or installed.

The procedure was:

1. Open the AEA using a read-only file stream.
2. Construct an encryption context and supply the catalog's 32-byte symmetric key.
3. Decode the outer archive; for each extraction metadata record, present its bounded `DAT` blob as a nested input stream.
4. Accept only regular files with exact allowlisted archive paths.
5. Enforce a size limit before allocating or writing selected data.
6. Reject duplicate selected entries and refuse to overwrite existing output files.
7. Traverse to the end and verify that every requested member was found.

The metadata allowlist was the eight files in the findings checksum table, with a 16 MiB per-member cap. The kernel pass accepted only `AssetData/boot/kernelcache.release.homeaccessory17`, with a 256 MiB cap. No archive-provided symlinks, ownership changes, or execution requests were applied.

The temporary source is `/tmp/homeview-reference.nV4CM5/ExtractFirmware.swift`; the compiled helper is `extract-firmware` in the same directory. These paths are ephemeral, and the source is not maintained in `Research/` at the owner's request. The pinned upstream reader and this procedure are the durable references. Reconstruct and review the allowlist and bounds before a future run if the temporary source is gone.

The helper's interface is:

```text
extract-firmware INPUT_AEA OUTPUT_DIRECTORY BASE64_KEY metadata|kernel
```

The recorded sample key from the reference catalog is:

```text
C6bVk4JwejgY6PfCJTX/nbrw/CtdphOG5EmsQMYe6As=
```

This is the update archive's recorded key, not a user account credential. Its suitability was verified by successful archive decoding; its publisher provenance was not independently authenticated.

Compilation without an explicit SDK failed with `unable to load standard library for target 'arm64-apple-macosx27.0.0'`. Compilation succeeded with the installed macOS SDK and an explicit macOS 15 target:

```sh
/Applications/Xcode.app/Contents/Developer/Toolchains/XcodeDefault.xctoolchain/usr/bin/swiftc \
  -sdk /Applications/Xcode.app/Contents/Developer/Platforms/MacOSX.platform/Developer/SDKs/MacOSX.sdk \
  -target arm64-apple-macosx15.0 \
  -module-cache-path /tmp/homeview-reference.nV4CM5/ModuleCache \
  /tmp/homeview-reference.nV4CM5/ExtractFirmware.swift \
  -o /tmp/homeview-reference.nV4CM5/extract-firmware
```

This deployment target does not prove that this specific OTA can be decoded on macOS 15. All successful decoding here happened on macOS 27.0.1.

## Plist and manifest checks

Python's `plistlib` parsed the extracted plists. Version/build fields and supported-product sets were compared across the outer metadata, BuildManifest, and SystemVersion. Both BuildIdentities were inspected separately. Component paths were compared rather than assuming that one board aliases the other.

For each device tree and the kernel container, the full extracted IM4P file's SHA-384 was compared to the corresponding `Manifest` entry's `Digest`. All four board/component comparisons for the trees and kernel succeeded. Package metadata was not treated as an Apple signature-validation result.

## Device-tree inspection

The temporary inspection code read DER tags and lengths, checked the IM4P type `dtre`, and passed the payload to the system `compression_decode_buffer` using `COMPRESSION_LZFSE` (`0x801`). Each output buffer was capped at 4 MiB. Both payloads decoded well below that cap.

The flat-tree parser read little-endian node counts, 32-byte property names, the length/flags fields, four-byte-aligned property data, and child nodes. Buffer bounds and complete consumption of decoded data were checked. The field layout was cross-checked against the reference parser. The initial diagnostic printer incorrectly collapsed paths to `/`; it was corrected and rerun before node paths were used in the findings. No tree content was changed.

## Kernel inspection

1. Parse the IM4P DER sequence and confirm type `krnl` and LZFSE payload magic `bvx2`.
2. Compare the original container digest to both KernelCache manifest entries.
3. Decompress with a buffer bounded by `256 MiB - container size`. Refuse a zero or capacity-sized result.
4. Confirm the decoded little-endian 64-bit Mach-O magic.
5. Parse the outer load-command region with bounds checks. Enumerate `LC_FILESET_ENTRY` records and locate `com.apple.kernel`.
6. Parse the embedded kernel header at its fileset offset and read the kernel version string.
7. Write only the decoded kernel to `analysis/firmware-metadata/AssetData/boot/kernelcache.release.homeaccessory17.macho`, refusing overwrite.

The container and decoded file together occupy 89,672,400 content bytes, below the authorized 256 MiB output bound. Checksums are in the findings.

Independent header checks:

```sh
file analysis/firmware-metadata/AssetData/boot/kernelcache.release.homeaccessory17.macho
/usr/bin/otool -hv analysis/firmware-metadata/AssetData/boot/kernelcache.release.homeaccessory17.macho
```

SDK evidence: `mach/machine.h` defines `CPU_SUBTYPE_MASK=0xff000000` and `CPU_SUBTYPE_ARM64E=2`; `mach-o/loader.h` defines `MH_FILESET=0xc`. The installed headers corroborate the numeric interpretation.

## Validation limits

No Apple firmware was executed, mounted, restored to hardware, or patched. No security setting changed. No account, pairing, HomeKit, audio, networking, or product performance behavior was tested. Subsequent userland/cache/PAC inspection is recorded in [Userland findings](USERLAND_FINDINGS.md); the self-authored CPU probe is separate from firmware execution. Complete extraction is recorded in [Complete extraction](FULL_EXTRACTION.md), and validation in [Validation](VALIDATION.md). These checks establish content consistency and static execution requirements, not bootability or full publisher authenticity.

## Subsequent streaming userland inspection

A temporary reader descended directly from each outer payload member through its decompression stream and into the filesystem archive. It scanned all 47 chunks without staging them, inventoried directories/regular files/links, and wrote selected regular files in fixed-size blocks. It refused parent traversal, unsupported write destinations and existing output files, and applied size bounds before writes. The follow-up pass selected seven additional actual service/audio paths discovered from the first inventory. Selected content and SHA-256 results are in `analysis/userland/inventory.json` and `additional-inventory.json`.

Per-file LLVM disassembly and `dyld_info` output were saved in `analysis/userland/audit/`. Cache-header fields were consulted in Apple's dyld source, then checked against local mapping bounds, image magic and load-command sizes. No shared-cache image was executed or modified. Subsequent complete expansion reused the identified payload format and restored links only after writing content, as detailed separately.
