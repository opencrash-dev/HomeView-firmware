//
//  Verification.swift
//  HomeView-firmware
//
//  Created by Phineas Guo on 2026/11/01.
//

import Darwin
import Foundation

public enum FirmwareVerification {
    @discardableResult
    public static func verify(root: URL, ledger: URL, inventory: URL? = nil,
                              links: URL? = nil, fixup: URL? = nil) throws -> Int {
        struct Files: Decodable { var completed: Bool; var regular_files: [FileRecord] }
        let records = try readJSON(Files.self, from: ledger)
        try require(records.completed, "Extraction ledger is incomplete")
        let base = root.resolvingSymlinksInPath()
        var seen = Set<String>()
        for (index, record) in records.regular_files.enumerated() {
            let path = try canonicalPath(record.path)
            try require(!path.isEmpty && seen.insert(path).inserted, "Duplicate or empty ledger path")
            let measured = try hashFile(checkedURL(root: base, path: path))
            try require(measured.size == record.size && measured.sha256 == record.sha256, "Content mismatch: \(path)")
            if (index + 1).isMultiple(of: 10000) { print("Verified \(index + 1) data files") }
        }
        try require((inventory == nil) == (links == nil), "Inventory and links must be supplied together")
        if let inventory, let links {
            let prior = try readJSON(PayloadInventory.self, from: inventory)
            try require(prior.completed, "Inventory is incomplete")
            let linkText = String(decoding: try boundedData(links, limit: 16 << 20), as: UTF8.self)
            let plan = try LinkPlan(entries: prior.entries, linkText: linkText)
            try require(seen == Set(plan.expected.keys), "Ledger/inventory data path mismatch")
            for (source, destination) in plan.hardlinks {
                let a = try fileStatus(checkedURL(root: base, path: source))
                let b = try fileStatus(checkedURL(root: base, path: destination))
                try require(a.st_dev == b.st_dev && a.st_ino == b.st_ino, "Hard-link inode mismatch: \(destination)")
            }
            for directory in plan.directories where !directory.isEmpty {
                let status = try fileStatus(checkedURL(root: base, path: directory))
                try require(status.st_mode & S_IFMT == S_IFDIR, "Expected directory: \(directory)")
            }
            for (path, target) in plan.symlinks {
                // Check ancestors without following the final guest symlink.
                let parent = (path as NSString).deletingLastPathComponent
                let url = try checkedURL(root: base, path: parent).appendingPathComponent((path as NSString).lastPathComponent)
                let status = try fileStatus(url)
                try require(status.st_mode & S_IFMT == S_IFLNK, "Expected symlink: \(path)")
                try require(try FileManager.default.destinationOfSymbolicLink(atPath: url.path) == target,
                            "Symlink target mismatch: \(path)")
            }
            if let fixup {
                let entries = try readJSON([EntryRecord].self, from: fixup)
                var expected = Dictionary(uniqueKeysWithValues: prior.entries.map { ($0.path, $0.type) })
                for (_, destination) in plan.hardlinks { expected[destination] = 70 }
                var actual: [String: UInt64] = [:]
                for entry in entries {
                    let path = try canonicalPath(entry.path)
                    try require(actual[path] == nil, "Duplicate fixup path")
                    actual[path] = entry.type
                }
                try require(actual == expected, "Fixup path/type set mismatch")
            }
        } else { try require(fixup == nil, "Fixup verification requires inventory and links") }
        return records.regular_files.count
    }
}
