//
//  SystemExpansion.swift
//  HomeView-firmware
//
//  Created by Phineas Guo on 2026/11/01.
//

import Foundation

struct LinkPlan {
    var expected: [String: UInt64] = [:]
    var directories = Set<String>()
    var symlinks: [String: String] = [:]
    var hardlinks: [(source: String, destination: String)] = []

    init(entries: [EntryRecord], linkText: String) throws {
        var all = Set<String>()
        for entry in entries {
            let path = try canonicalPath(entry.path)
            try require(all.insert(path).inserted, "Duplicate inventory path: \(path)")
            switch entry.type {
            case 70:
                try require(!path.isEmpty && entry.size != nil, "Missing file path or size")
                expected[path] = entry.size!
            case 68: directories.insert(path)
            case 76:
                guard !path.isEmpty, let target = entry.link, !target.contains("\0") else {
                    throw FirmwareError("Invalid symlink record")
                }
                symlinks[path] = target
            default: throw FirmwareError("Unsupported inventory entry type: \(entry.type)")
            }
        }
        var source: String?
        for line in linkText.split(whereSeparator: \.isNewline) {
            let path = try canonicalPath(String(line.dropFirst()))
            try require(!path.isEmpty, "Empty hard-link path")
            if line.first == "=" {
                try require(expected[path] != nil, "Hard-link source is not a data file")
                source = path
            } else if line.first == "+", let source {
                try require(all.insert(path).inserted, "Duplicate hard-link destination")
                hardlinks.append((source, path))
            } else { throw FirmwareError("Malformed links.txt record") }
        }
        let hardlinkDestinations = Set(hardlinks.map(\.destination))
        for path in all {
            var parent = (path as NSString).deletingLastPathComponent
            while !parent.isEmpty && parent != "." {
                try require(symlinks[parent] == nil && expected[parent] == nil,
                            "File or symlink used as parent: \(parent)")
                try require(!hardlinkDestinations.contains(parent), "Hard link used as parent")
                parent = (parent as NSString).deletingLastPathComponent
            }
        }
    }
}

extension PayloadTools {
    @discardableResult
    public static func expand(ota: URL, inventory: URL, output: URL) throws -> ExpansionLedger {
        let prior = try readJSON(PayloadInventory.self, from: inventory)
        try require(prior.completed, "Inventory is incomplete")
        let payload = try payloadDirectory(ota)
        let links = String(decoding: try boundedData(payload.appendingPathComponent("links.txt"), limit: 16 << 20), as: UTF8.self)
        let plan = try LinkPlan(entries: prior.entries, linkText: links)
        let indices = try chunkIndices(String(decoding: boundedData(payload.appendingPathComponent("payload_chunks.txt"), limit: 16 << 20), as: UTF8.self))
        try require(prior.chunks == indices.map { "AssetData/payloadv2/" + String(format: "payload.%03d", $0) },
                    "Inventory chunk set differs from payload index")
        let ledgerURL = output.deletingLastPathComponent().appendingPathComponent(output.lastPathComponent + ".expansion.json")
        try require(!pathExists(ledgerURL), "Expansion ledger already exists")
        try newDirectory(output)
        var observed = Set<String>()
        var records: [FileRecord] = []
        var total: UInt64 = 0
        for index in indices {
            let name = String(format: "payload.%03d", index)
            try ArchiveReader.compressed(checkedURL(root: payload, path: name)) { stream in
                while let header = try stream.readHeader() {
                    guard let record = try header.record() else { continue }
                    if record.type == 68 {
                        try require(plan.directories.contains(record.path), "Unexpected directory")
                        continue
                    }
                    if record.type == 76 {
                        try require(plan.symlinks[record.path] == record.link, "Symlink inventory mismatch")
                        continue
                    }
                    let size = record.size ?? 0
                    try require(record.type == 70 && plan.expected[record.path] == size,
                                "Payload file not in inventory: \(record.path)")
                    try require(observed.insert(record.path).inserted, "Duplicate payload file")
                    try require(size <= 8 << 30 && total <= (40 << 30) - size, "Expansion size limit exceeded")
                    let url = try checkedURL(root: output, path: record.path)
                    records.append(try ArchiveReader.writeBlob(stream, size: size, to: url, path: record.path))
                    total += size
                }
            }
            print("Expanded \(name): \(records.count) files")
        }
        try require(observed == Set(plan.expected.keys), "Payload files missing from expansion")
        for path in plan.directories where !path.isEmpty {
            try FileManager.default.createDirectory(at: checkedURL(root: output, path: path), withIntermediateDirectories: true)
        }
        for (source, destination) in plan.hardlinks {
            let target = try checkedURL(root: output, path: destination)
            try FileManager.default.createDirectory(at: target.deletingLastPathComponent(), withIntermediateDirectories: true)
            try FileManager.default.linkItem(at: checkedURL(root: output, path: source), to: target)
        }
        // Preserve guest targets verbatim, including absolute guest paths. No later writes follow them.
        for (path, target) in plan.symlinks.sorted(by: { $0.key < $1.key }) {
            let url = try checkedURL(root: output, path: path)
            try FileManager.default.createDirectory(at: url.deletingLastPathComponent(), withIntermediateDirectories: true)
            try FileManager.default.createSymbolicLink(atPath: url.path, withDestinationPath: target)
        }
        let result = ExpansionLedger(completed: true, regular_files: records, regular_content_bytes: total,
                                     hard_links: plan.hardlinks.count, symbolic_links: plan.symlinks.count)
        try writeJSON(result, to: ledgerURL)
        return result
    }
}
