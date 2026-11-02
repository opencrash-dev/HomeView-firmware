# Firmware Research Sources

## Archive reader

- [vphone-cli](https://github.com/Lakr233/vphone-cli), inspected revision `57bbc93c5a3498919f2cea0ed0be60d83e28055b`.
- [OTA archive implementation](https://github.com/Lakr233/vphone-cli/blob/57bbc93c5a3498919f2cea0ed0be60d83e28055b/VPhoneKit/VPhoneArchiveKit/Transfer/VPhoneOTAArchive.swift).

Code attribution and licensing are preserved in THIRD_PARTY_NOTICES.md at the repository root.

## Original format definitions

- [Apple dyld](https://github.com/apple-oss-distributions/dyld): shared-cache mappings, Mach-O loading and chained fixups.
- [Apple XNU](https://github.com/apple-oss-distributions/xnu): architecture constants, Mach-O and kernel interfaces.
- Installed macOS SDK AppleArchive, Compression, CryptoKit and System interfaces: archive decoding, bounded decompression and hashing APIs.

## Evidence standard

The supplied archive, extracted bytes, manifest digests, header fields and independent file rereads are the primary evidence for sample-specific claims. Reference reports are leads rather than substitute measurements. A matching digest establishes content consistency within the stated comparison, not a complete publisher certificate-chain verification. No original firmware executable was run in the documented static investigation.
