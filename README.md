# HomeView Firmware Research

HomeView firmware research and a macOS Swift Package executable.

## Usage

Requires Swift 6 and macOS 15 or later. Tested with macOS 27.0.1.

```sh
swift build
swift test
swift run homeview-firmware --help
swift run homeview-firmware extract --input update.aea --output metadata --mode metadata --key-file key.txt
```

The key file contains a Base64-encoded 32-byte key. Commands: `extract`, `inventory`, `expand`, `fixup`, `decode`, `tree`, `macho`, `hash`, `verify`. See `--help` for arguments. Outputs must be new paths. No external Swift dependencies are required.

Research is preserved in `Research/`. Python analysis utilities are retained in `Tools/Reference`; the Swift executable does not invoke them.

Extraction is not a bootable restore or publisher signature verification. Ownership, flags and xattrs are not applied. Firmware and generated data are not included.

## Acknowledgements

- [vphone-cli](https://github.com/Lakr233/vphone-cli)
- [UniXNU](https://github.com/UniXNU/UniXNU)
- [Apple Open Source](https://github.com/apple-oss-distributions)

## License

MIT. See LICENSE and THIRD_PARTY_NOTICES.md.
