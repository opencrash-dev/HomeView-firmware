# Complete AEA and System Content Expansion

Date: 2026-11-01 (Asia/Shanghai).

## Authorization and storage

The owner replaced `analysis` with a symbolic link to `/Volumes/Zonglin's Disk/analysis-homeview` and authorized complete AEA extraction. The target initially returned `Operation not permitted`, including with elevated command execution. After the owner's follow-up, a fresh access check succeeded. The extraction proceeded only after that check; no host privacy or security setting was changed by the agent.

The external volume reported approximately 106 GiB available before full extraction. New output directories were used, preserving the original AEA and all previous analysis products:

| Location relative to `analysis/` | Contents |
| --- | --- |
| `full-ota/` | All regular files and directory records from the outer segmented AEA |
| `full-ota/EXTRACTION_COMPLETE.json` | Outer file sizes, SHA-256 hashes, directory records, completion state |
| `system-root/` | Fully expanded main payload content tree, including restored links |
| `SYSTEM_EXPANSION_COMPLETE.json` | Main regular-file sizes/hashes and link counts |
| `fixup-records.json` | Parsed metadata fixup records, without applying privileged attributes |
| `full-validation/` | Independent verification and standalone Mach-O inventory |

`Research/` contains Markdown explanations only. These binary and machine-readable artifacts stay on the external analysis volume.

## Outer archive

The bounded system-API reader traversed the encrypted AEA and every nested extraction segment. It wrote all 170 regular files and created the 27 directory records. The regular-file content total is 6,645,798,369 bytes (approximately 6.19 GiB). The reader imposed an 8 GiB per-file and 32 GiB cumulative bound, refused overwrite, and rejected absolute paths and parent traversal.

The wrapper contains the boot firmware, kernel, ExclaveOS DMG, update indexes, ECC files, all 47 main payload chunks, and auxiliary update streams. Outer metadata ownership/fixup operations were not executed against the host.

The original AEA remains in the project root and has not been renamed, modified, or committed.

## Main system payload

The expansion reader opened each staged `payload.000` through `payload.046`, decompressed it through AppleArchive, and restored the complete regular-file content. No selective filter was used for the main system pass.

| Record kind | Count |
| --- | ---: |
| Directory records | 23,718 |
| Regular files carrying data in the payload | 172,672 |
| Hard-link destinations from `links.txt` | 13,706 |
| Symbolic links | 193 |
| Total final path records | 210,289 |

Regular content carrying independent payload data totals 13,914,159,280 bytes (approximately 12.96 GiB). Hard links add names, not independent copies of their source data. The expansion used an 8 GiB per-file and 40 GiB cumulative regular-content bound.

The final metadata fixup manifest lists 186,378 regular-file paths, exactly the 172,672 payload files plus 13,706 hard-link destinations; it also lists 23,718 directories and 193 symlinks. The complete path/type set is compared during validation, rather than relying only on these matching counts.

## Links and host isolation

All paths were preflighted against the prior complete payload inventory. The extraction refused traversal components and any member beneath an archive-provided symlink. Regular files were written before links. Hard-link sources were verified to be payload regular files; all 13,706 destinations were absent from the payload's original path set and unique.

Symbolic links were created last, preserving the original target strings. Of the 193 links, 148 have guest-absolute targets. Those target strings belong to the guest filesystem, not to the host. Analysis and validation do not resolve or traverse them. Do not treat a host path reached through such a link as donor evidence.

Ownership, BSD flags, xattrs, filesystem compression, APFS volume roles/seals, and restore operations were not applied. The result is a complete static content/link tree for research, not a claim of a bootable or metadata-identical restored installation. The raw fixup manifest is retained for future interpretation.

## Index and auxiliary streams

- `payload_chunks.txt` enumerates 47 consecutive indices, 0 through 46; every corresponding staged chunk exists.
- Its size column does not equal the compressed chunk file lengths. No claim of corruption or validated size semantics is made from that difference. The reference project's check validates indices, not that size column.
- `data_payload` and `prepare_payload` are each 12-byte `pbzm` streams; the installed `aa list -v` completed without listing filesystem records.
- `firmlinks_payload` is empty.
- `fixup.manifest` is a compressed metadata archive. It was decoded and inventoried; its ownership/flag requests were not applied.
- Boot DMGs and firmware components were extracted as files. They were not mounted, flashed, or executed.

## Additional findings enabled by the full tree

- `/System/Library/LaunchDaemons/com.apple.usbaudiod.plist` starts `/System/Library/Audio/Plug-Ins/usbaudio.bundle/usbaudiod` as mobile and advertises `com.apple.usbaudiod`.
- The acoustic calibration daemon has its own launch configuration and service, separate from basic USB audio enumeration.
- `/usr/libexec/perceptiond` advertises `com.apple.perceptiond.entitykit` and `com.apple.perceptiond.api`.
- usermanagerd advertises both `com.apple.mobile.usermanagerd.xpc` and `com.apple.mobile.keybagd.UserManager.xpc`. An endpoint declaration is not proof of successful runtime service behavior.
- `MTLCompilerService.xpc` is present inside Metal.framework, with bundle identifier `com.apple.MTLCompilerService`. Its absence from the launch-daemon filename search did not mean that the service was absent.
- The AGXMetalG17P bundle's Info.plist identifies `com.apple.AGXMetalG17P`. The matching image exists in the shared cache.
- BreadBoardFramework and BackBoardServices are not present as ordinary standalone executable files at their framework paths in the full tree. Their mapped Mach-O images were located in the shared cache. Fully expanding the OTA does not automatically reconstruct cached dylibs as standalone files for Hopper.

## Reproduction outline

Temporary helpers are `/tmp/homeview-reference.nV4CM5/ExtractAll.swift`, `ExpandSystem.swift`, and `InspectFixup.swift`. They use the pinned reference's bounded segment adapter with its MIT notice retained, plus project-specific extraction and validation logic. They were compiled with the explicit SDK/deployment options recorded in [Methods](METHODS.md).

Their interfaces are:

```text
extract-all INPUT_AEA NEW_OUTER_DIRECTORY BASE64_KEY
expand-system OUTER_DIRECTORY NEW_SYSTEM_DIRECTORY PRIOR_PAYLOAD_INVENTORY_JSON
inspect-fixup FIXUP_MANIFEST NEW_OUTPUT_JSON
```

These temporary paths may disappear. The raw archives, inventories, hashes, and documented API procedure are the durable evidence. A future reconstruction must preserve the same preflight checks and must not blindly follow guest-absolute links.

See [Validation](VALIDATION.md) for the completed independent checks.
