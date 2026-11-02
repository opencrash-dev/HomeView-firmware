# Swift firmware tools

The root Swift Package consolidates temporary archive readers into FirmwareKit and the homeview-firmware executable. Commands cover encrypted extraction, payload inventory, expansion, fixup metadata, IM4P decoding, device trees, Mach-O headers, hashing and verification. See the root README and executable --help.

Real-sample validation: eight metadata files, 152,892 bytes, matched earlier extraction byte for byte; Mach-O inspection identified 236 fileset entries; J490 device-tree decoding and parsing succeeded. Full production expansion has not been repeated. Final synthetic tests require a rerun after fixture corrections; no passing final suite is claimed.

Historical documents are retained as snapshots. Guest links are preserved, but ownership, flags and xattrs are not restored. Use a private output without concurrent writers. Deep chained-pointer and syscall audits remain in Tools/Reference Python utilities.
