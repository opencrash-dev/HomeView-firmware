# Firmware Validation Record

## Sample and metadata

The original AEA SHA-256 is `03b7b44bbe09fa033cd35077d8e5c3455b227d86ce7a528ecc6ef2165635f570`. Metadata version/build/product fields were cross-checked. Device-tree and kernel IM4P SHA-384 values matched the corresponding BuildManifest digests. Decoded trees and kernel headers were checked for buffer bounds.

## Extracted content

The earlier full extraction independently verified 170 outer regular files and 172,672 system data files by size and SHA-256; 13,706 hard links by inode; 193 symbolic links by literal target; 23,718 directories; 210,289 final fixup path/type records; and 47 consecutive payload indices. No ownership, flags or xattrs were applied. This describes the historical extraction, not a full rerun of the maintained package.

The selected-userland survey checked 720 files and parsed 643 plists. It inspected 2,904 shared-cache image headers. All reported arm64e. The standalone-file survey found one plain-arm64 STExtractionService executable; this is not an alternative startup stack.

## Swift package checkpoint

The package compiled on macOS 27.0.1 with Swift 6.4. Eight metadata files totaling 152,892 bytes matched the earlier extraction byte for byte. Kernel header inspection identified 236 fileset entries. The J490 device tree decoded and parsed successfully.

Synthetic archive tests exposed malformed test fixtures. Corrections were saved, but the final complete test suite has not been rerun; no passing complete suite is claimed. Full production expansion has not been repeated using this package.

## Limits

No firmware execution, restore, mounting, patching or complete publisher signature validation is established by these checks. Generated artifacts and proprietary firmware are excluded from version control. See [Swift tooling](TOOLING.md) for commands and [Methods](METHODS.md) for historical procedures.
