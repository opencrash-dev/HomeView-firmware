//
//  PayloadInventory.swift
//  HomeView-firmware
//
//  Created by Phineas Guo on 2026/11/01.
//

import Foundation

public enum SelectionProfile: String, Sendable {
    case none, startup, additional

    func contains(_ path: String) -> Bool {
        switch self {
        case .none: return false
        case .additional:
            return ["System/Library/PrivateFrameworks/UserProfilesDaemon.framework/Support/userprofilesd",
                    "usr/sbin/wifid", "usr/sbin/mDNSResponder", "usr/libexec/configd",
                    "Library/Audio/Plug-Ins/HAL/VirtualAudio.plugin/VirtualAudio",
                    "Library/Audio/Plug-Ins/HAL/PapagaioPlugin.driver/PapagaioPlugin",
                    "Library/Audio/Plug-Ins/HAL/PiperPlugin.driver/PiperPlugin"].contains(path)
        case .startup:
            let lower = path.lowercased()
            return ["usr/lib/dyld", "sbin/launchd", "usr/sbin/mediaserverd", "usr/libexec/backboardd",
                    "usr/libexec/userprofilesd", "usr/libexec/audiomxd", "usr/libexec/audioclocksyncd",
                    "usr/libexec/airplayd", "usr/libexec/tvairplayd"].contains(path)
                || (path.contains("dyld_shared_cache") && !path.hasSuffix(".map"))
                || (path.hasPrefix("System/Library/LaunchDaemons/") && path.hasSuffix(".plist"))
                || (path.hasSuffix(".plist") && ["audio", "breadboard", "homeview"].contains(where: lower.contains))
                || path.contains("BreadBoard.app/") || path.contains("Setup.app/Info.plist")
        }
    }
}

public enum PayloadTools {
    static func payloadDirectory(_ ota: URL) throws -> URL {
        try checkedURL(root: ota.resolvingSymlinksInPath(), path: "AssetData/payloadv2")
    }

    public static func chunkIndices(_ contents: String) throws -> [Int] {
        let rows = contents.split(whereSeparator: \.isNewline)
        try require(!rows.isEmpty && rows.count <= 1000, "Invalid payload chunk count")
        return try rows.enumerated().map { index, line in
            guard let value = Int(line.split(separator: ":", omittingEmptySubsequences: false)[0]), value == index else {
                throw FirmwareError("Nonconsecutive payload index at line \(index + 1)")
            }
            return value
        }
    }

    @discardableResult
    public static func inventory(ota: URL, output: URL, selection: SelectionProfile) throws -> PayloadInventory {
        let payload = try payloadDirectory(ota)
        let indices = try chunkIndices(String(decoding: boundedData(payload.appendingPathComponent("payload_chunks.txt"), limit: 16 << 20), as: UTF8.self))
        try newDirectory(output)
        var entries: [EntryRecord] = []
        var files: [FileRecord] = []
        var chunks: [String] = []
        var seen = Set<String>()
        var selectedBytes: UInt64 = 0
        for index in indices {
            let name = String(format: "payload.%03d", index)
            let input = try checkedURL(root: payload, path: name)
            try ArchiveReader.compressed(input) { stream in
                while let header = try stream.readHeader() {
                    guard let record = try header.record(chunk: "AssetData/payloadv2/" + name) else { continue }
                    try require(entries.count < 1_000_000, "Inventory entry limit exceeded")
                    entries.append(record)
                    guard record.type == 70, selection.contains(record.path) else { continue }
                    let size = record.size ?? 0
                    try require(size <= 2 << 30 && selectedBytes <= (8 << 30) - size,
                                "Selected-content size limit exceeded")
                    try require(!seen.contains(record.path), "Duplicate selected file")
                    let url = try checkedURL(root: output, path: "files/" + record.path)
                    files.append(try ArchiveReader.writeBlob(stream, size: size, to: url, path: record.path))
                    seen.insert(record.path)
                    selectedBytes += size
                }
            }
            chunks.append("AssetData/payloadv2/" + name)
            print("Scanned \(name): \(entries.count) entries")
        }
        let result = PayloadInventory(completed: true, chunks: chunks, entries: entries,
                                      extracted: files, selected_bytes: selectedBytes)
        try writeJSON(result, to: output.appendingPathComponent("inventory.json"))
        return result
    }

    @discardableResult
    public static func fixup(input: URL, output: URL) throws -> Int {
        var entries: [EntryRecord] = []
        try ArchiveReader.compressed(input) { stream in
            while let header = try stream.readHeader() {
                if let record = try header.record() {
                    try require(entries.count < 1_000_000, "Fixup entry limit exceeded")
                    entries.append(record)
                }
            }
        }
        try writeJSON(entries, to: output)
        return entries.count
    }
}
