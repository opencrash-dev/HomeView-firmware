# HomeView Firmware Research

This repository documents static analysis of HomeView firmware and maintains extraction and inspection tools. It contains no firmware binaries or extracted system content.

## Research index

- [Firmware identity and components](FIRMWARE_FINDINGS.md)
- [Userland, frameworks, services and drivers](USERLAND_FINDINGS.md)
- [Extraction and inspection methods](METHODS.md)
- [Complete archive and system expansion](FULL_EXTRACTION.md)
- [Validation evidence and limits](VALIDATION.md)
- [Swift tooling](TOOLING.md)
- [Sources](SOURCES_AND_HISTORY.md)

The inspected sample is HomeView 27.2, build 24V514. Its original kernel identifies as XNU 13432.43.4~16. Startup executables and the main shared cache are arm64e. These are static observations, not runtime compatibility results.

Machine-readable ledgers and proprietary artifacts remain in an external analysis workspace. Historical extraction records refer to that workspace; those paths are not bundled dependencies. Research documents use English. Tool usage is documented in the root README.
