# Local Firmware Findings

Inspection date: 2026-11-01 (Asia/Shanghai).

All observations below refer to the supplied sample. They are not claims about every HomeView release.

## 1. Source artifact

| Property | Observation |
| --- | --- |
| Filename | `91e6292d137569817d83050e9a21c6c93c25af6ab02fbaa7eeddb9ad5439b99a.aea` |
| Size | 6,509,559,808 bytes |
| Magic | `AEA1` |
| SHA-256 | `03b7b44bbe09fa033cd35077d8e5c3455b227d86ce7a528ecc6ef2165635f570` |
| Archive profile reported by `aa` | `hkdf_sha256_aesctr_hmac__symmetric__none` |
| Container structure | Segmented Apple Archive with nested extraction streams |

The filename matches the AEA archive identifier reported by `aa`; it is not the measured SHA-256. The recorded catalog size matches the local file. No independently authenticated publisher checksum or Apple signing-chain validation has been performed.

## 2. Version and platform

The outer `Info.plist`, boot `BuildManifest.plist`, and boot `SystemVersion.plist` agree on version `27.2` and build `24V514`. The outer supported-product list and BuildManifest both contain `HomeAccessory17,1` and `HomeAccessory17,2`.

| Field | Value |
| --- | --- |
| `SystemVersion.ProductName` | `Apple TVOS` |
| Build train | `LotusLeafB` |
| Restore long version | `24.22.514.0.0,0` |
| BuildIdentity variant | `Customer Software Update` |
| Restore behavior | `Update` |
| Chip ID | `0x8140` |
| Platform in Restore.plist | `t8140` |

`AssetData/Info.plist` reports `ProductType=HomeAccessory17,1` alongside `HardwareModel=J491AP`. This mixed generic metadata must not be used alone to identify a board. Select a BuildIdentity and corroborate it with its device tree.

The outer `SupportedDeviceModels` includes both `J490AP` and `J491AP`. An older reference project's description of a supplied Pallas response naming only J490 is not a description of this locally parsed plist.

## 3. Board identities and component map

| Board | Device-tree root model | Board ID | Device-tree target |
| --- | --- | --- | --- |
| J490AP | `HomeAccessory17,1` | `0x02` | `J490` |
| J491AP | `HomeAccessory17,2` | `0x06` | `J491` |

Both identities reference the same paths for the following components:

- Kernel: `kernelcache.release.homeaccessory17`.
- Main OS image: `141-21962-183.dmg`.
- GPU firmware: `Firmware/agx/armfw_g17p.im4p` and `armfw1_g17p.im4p`.
- Display firmware: `Firmware/dcp/t8140dcp.im4p`.
- ExclaveOS image: `141-21782-189.dmg`.
- Restore ramdisk: `arm64eSURamDisk.dmg`.

Paths differ for DeviceTree/RestoreDeviceTree, LLB, iBoot, iBootData, iBSS, iBEC, Multitouch, SEP/RestoreSEP, and SepStage1. Shared paths do not establish that all runtime behavior is identical.

The named main OS DMG is a manifest reference. It has not been extracted or mounted, and its presence as a standalone archive member is not claimed. System reconstruction requires examining the OTA payload format.

## 4. Device-tree observations

Both `dtre` IM4P payloads begin with LZFSE magic `bvx2`. Decompression and a bounded recursive parse consumed the complete decoded data: 271,196 bytes for J490 and 270,636 bytes for J491. Both original IM4P files match their respective BuildManifest SHA-384 digests.

| Node | Observed property | Interpretation boundary |
| --- | --- | --- |
| `/arm-io/spi1/multi-touch` | `compatible=hid-transport,thirdpartyspi` | Describes the donor's SPI touch transport, not USB touch compatibility |
| `/arm-io/dcp` | `compatible=iop,ascwrap-v6` | Display coprocessor description; actual driver activity is unverified |
| `/arm-io/apcie/pci-bridge0/wlan` | `compatible=wlan-pcie,mt7923` and `wlan-pcie,mt` | Firmware binding strings, not independent physical-chip identification |
| `/arm-io/aop/iop-aop-nub/aop-audio` | `compatible=iop-audio,aop-service` | An AOP audio service is described; its complete data path is unknown |
| `/arm-io/audio-resource-manager` | `compatible=audio,embedded-resource-manager` | Audio-resource service description |
| `/product` | `product-description=HomeView`, scale 2, subtype 1088 | Subtype alone does not prove physical resolution or PPI |

Device-tree descriptions do not prove that a driver loads, a service is used, or a listed peripheral is required by the desktop.

## 5. Kernel container and decoded Mach-O

| Property | Local result |
| --- | --- |
| IM4P type | `krnl` |
| IM4P description | `KernelManagement_host-514.40.8` |
| Container bytes | 21,318,352 |
| Compressed payload magic | `bvx2` (LZFSE) |
| Decoded bytes | 68,354,048 |
| Total container plus decoded output | 89,672,400 bytes, below the 256 MiB cap |
| Container SHA-256 | `e09e75497e37e27c65eb72672bff7076f16ae270de9735bdd82b99ba324a0424` |
| Decoded SHA-256 | `5494cb0794b93f78298629996c477ffe6a263ccf53bb143522a886fcaee55350` |

Both BuildIdentities contain a KernelCache SHA-384 digest matching the extracted container. This is internal consistency, not an independent authenticity proof.

The decoded outer header and embedded `com.apple.kernel` both report CPU type `0x0100000c` and subtype `0xc0000002`. Masking CPU feature bits gives base subtype 2, `CPU_SUBTYPE_ARM64E`, as defined by the installed SDK. `file` independently reports arm64e, and `otool -hv` reports `ARM64 E` and `FILESET` for the outer header.

| Mach-O property | Outer fileset | Embedded kernel |
| --- | --- | --- |
| File type | 12 (`MH_FILESET`) | 2 (`MH_EXECUTE`) |
| Load commands | 249 | 27 |
| Load-command bytes | 17,848 | 5,600 |
| File offset | 0 | 32,768 |

There are 236 `LC_FILESET_ENTRY` commands. The embedded kernel entry names `com.apple.kernel` and records VM address `0xfffffff00700c000`. This is a sample address, not a patch offset.

Recorded kernel version string:

```text
Darwin Kernel Version 27.2.0: Tue Oct 13 19:24:30 PDT 2026; root:xnu-13432.43.4~16/RELEASE_ARM64_T8140
```

This is a binary string observation. It does not establish source availability, successful execution, or compatibility with UniXNU's `12377` profiles. A header classification is not an instruction-by-instruction PAC audit.

## 6. Extracted metadata checksums

Paths below are relative to `analysis/firmware-metadata/`.

| Path | Bytes | SHA-256 |
| --- | ---: | --- |
| `Info.plist` | 3,322 | `6113886db9739f88513df6411e3ba2c396ea11eba304908a1b007e59da4c0bbf` |
| `AssetData/Info.plist` | 2,850 | `7b18557a8a7cbd9521355121f6bc7273cf4e0c9babf437fe4b1bf35575562fa7` |
| `AssetData/boot/BuildManifest.plist` | 46,833 | `1939fd31aa10e330fd5b93d87367a0be40d9ac81f59596353cf665b3d12dd6b2` |
| `AssetData/boot/Restore.plist` | 1,431 | `8e8265eb4d54ecea7d401c71bbc452e66eabcf67e3e401d5de5860862bb99b0a` |
| `AssetData/boot/RestoreVersion.plist` | 362 | `d5ad4d644302203386875af9464ee67854ca2262a53053529fc3230228a8172a` |
| `AssetData/boot/SystemVersion.plist` | 491 | `c14c3fb8cb846513d1602712e028fc699c32bea2e9a86467c42e58ccca573afa` |
| `AssetData/boot/Firmware/all_flash/DeviceTree.j490ap.im4p` | 48,848 | `5c52669222f37db5dd1d9422bf4956fee22964237f02c0204face8594bf05169` |
| `AssetData/boot/Firmware/all_flash/DeviceTree.j491ap.im4p` | 48,755 | `0c0cdc4e64211fc7bc13d41d63f717c4901ca7c484c6e370d05ca12bb45eea6e` |

These eight files total 152,892 bytes, excluding filesystem allocation and Finder metadata. No `.DS_Store` file is treated as firmware evidence.

## 7. Subsequent investigation

Actual userland architecture, instructions, fixups and dependency results are in [Userland findings](USERLAND_FINDINGS.md). The original package has since been completely expanded to an external analysis volume; see [Complete extraction](FULL_EXTRACTION.md). Those later stages extend the initial bounded metadata/kernel work without changing its sample identity or treating a content tree as a successful restore/boot.
