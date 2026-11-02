//
//  OTAExtractor.swift
//  HomeView-firmware
//
//  Created by Phineas Guo on 2026/11/01.
//

import Foundation

public enum ExtractionMode: String, CaseIterable, Sendable {
    case metadata, kernel, index, all

    var members: Set<String>? {
        switch self {
        case .metadata:
            return ["Info.plist", "AssetData/Info.plist", "AssetData/boot/BuildManifest.plist",
                    "AssetData/boot/SystemVersion.plist", "AssetData/boot/RestoreVersion.plist",
                    "AssetData/boot/Restore.plist", "AssetData/boot/Firmware/all_flash/DeviceTree.j490ap.im4p",
                    "AssetData/boot/Firmware/all_flash/DeviceTree.j491ap.im4p"]
        case .kernel: return ["AssetData/boot/kernelcache.release.homeaccessory17"]
        case .index: return ["AssetData/payloadv2/payload_chunks.txt", "AssetData/payloadv2/links.txt"]
        case .all: return nil
        }
    }
    var memberLimit: UInt64 {
        switch self {
        case .metadata, .index: return 16 << 20
        case .kernel: return 256 << 20
        case .all: return 8 << 30
        }
    }
}

public enum OTAExtractor {
    @discardableResult
    public static func extract(input: URL, output: URL, key: Data, mode: ExtractionMode) throws -> ExtractionLedger {
        try require(key.count == 32, "The AEA key must contain 32 bytes")
        try newDirectory(output)
        var files: [FileRecord] = []
        var seen = Set<String>()
        var directories = Set<String>()
        var total: UInt64 = 0
        try ArchiveReader.encrypted(input, key: key) { archive in
            try ArchiveReader.walk(archive) { header, stream in
                guard let record = try header.record() else { return }
                if record.type == 68 {
                    if mode == .all { directories.insert(record.path) }
                    return
                }
                if let wanted = mode.members, !wanted.contains(record.path) { return }
                try require(record.type == 70 && !record.path.isEmpty, "Unsupported outer archive entry: \(record.path)")
                try require(record.path != "EXTRACTION_COMPLETE.json", "Reserved ledger path")
                try require(!seen.contains(record.path), "Duplicate archive file: \(record.path)")
                let size = record.size ?? 0
                try require(size <= mode.memberLimit && total <= (32 << 30) - size, "Extraction size limit exceeded")
                let url = try checkedURL(root: output, path: record.path)
                files.append(try ArchiveReader.writeBlob(stream, size: size, to: url, path: record.path))
                total += size
                seen.insert(record.path)
            }
        }
        if let wanted = mode.members {
            try require(seen == wanted, "Missing requested members: \(wanted.subtracting(seen).sorted())")
        }
        for path in directories where !path.isEmpty {
            try FileManager.default.createDirectory(at: checkedURL(root: output, path: path), withIntermediateDirectories: true)
        }
        let ledger = ExtractionLedger(completed: true, regular_files: files,
                                      directories: directories.sorted(), content_bytes: total)
        try writeJSON(ledger, to: output.appendingPathComponent("EXTRACTION_COMPLETE.json"))
        return ledger
    }
}
