//
//  Support.swift
//  HomeView-firmware
//
//  Created by Phineas Guo on 2026/11/01.
//

import CryptoKit
import Foundation
import Darwin

public struct FirmwareError: Error, CustomStringConvertible, Sendable {
    public let description: String
    public init(_ message: String) { description = message }
}

func require(_ condition: @autoclosure () throws -> Bool, _ message: String) throws {
    guard try condition() else { throw FirmwareError(message) }
}

public func canonicalPath(_ original: String) throws -> String {
    var path = original
    while path.hasPrefix("./") { path.removeFirst(2) }
    try require(!path.hasPrefix("/") && !path.contains("\0"), "Absolute or NUL-containing archive path")
    let parts = path.split(separator: "/", omittingEmptySubsequences: false)
    try require(!parts.contains("..") && !parts.contains("."), "Noncanonical archive path: \(original)")
    try require(path.isEmpty || !parts.contains(""), "Empty archive path component: \(original)")
    return path
}

func pathExists(_ url: URL) -> Bool {
    var info = stat()
    return url.path.withCString { lstat($0, &info) } == 0
}

func fileStatus(_ url: URL) throws -> stat {
    var info = stat()
    guard url.path.withCString({ lstat($0, &info) }) == 0 else {
        throw FirmwareError("Cannot stat \(url.path): \(String(cString: strerror(errno)))")
    }
    return info
}

/// Call before opening a path: guest symlinks must never resolve into the host.
func checkedURL(root: URL, path: String) throws -> URL {
    let clean = try canonicalPath(path)
    var result = root
    for component in clean.split(separator: "/") {
        result.appendPathComponent(String(component))
        if pathExists(result) {
            let status = try fileStatus(result)
            try require(status.st_mode & S_IFMT != S_IFLNK, "Refusing symlink traversal: \(result.path)")
        }
    }
    return result
}

func newDirectory(_ url: URL) throws {
    try require(!pathExists(url), "Output must be a new directory: \(url.path)")
    let parent = url.deletingLastPathComponent().resolvingSymlinksInPath()
    try require(parent.hasDirectoryPath || FileManager.default.fileExists(atPath: parent.path), "Output parent is missing")
    try FileManager.default.createDirectory(at: url, withIntermediateDirectories: true)
}

func writeJSON<T: Encodable>(_ value: T, to url: URL) throws {
    let encoder = JSONEncoder()
    encoder.outputFormatting = [.sortedKeys, .prettyPrinted, .withoutEscapingSlashes]
    try encoder.encode(value).write(to: url, options: .withoutOverwriting)
}

func readJSON<T: Decodable>(_ type: T.Type, from url: URL) throws -> T {
    try JSONDecoder().decode(type, from: Data(contentsOf: url))
}

func hex<D: Sequence>(_ digest: D) -> String where D.Element == UInt8 {
    digest.map { String(format: "%02x", $0) }.joined()
}

public struct FileRecord: Codable, Sendable, Equatable {
    public var path: String
    public var size: UInt64
    public var sha256: String
}

public struct EntryRecord: Codable, Sendable {
    public var path: String
    public var type: UInt64
    public var size: UInt64?
    public var chunk: String?
    public var link: String?
    public var UID: UInt64?
    public var GID: UInt64?
    public var MOD: UInt64?
    public var FLG: UInt64?
}

public struct ExtractionLedger: Codable, Sendable {
    public var completed: Bool
    public var regular_files: [FileRecord]
    public var directories: [String]
    public var content_bytes: UInt64
    public var ownership_and_flags_applied = false
}

public struct PayloadInventory: Codable, Sendable {
    public var completed: Bool
    public var chunks: [String]
    public var entries: [EntryRecord]
    public var extracted: [FileRecord]
    public var selected_bytes: UInt64
}

public struct ExpansionLedger: Codable, Sendable {
    public var completed: Bool
    public var regular_files: [FileRecord]
    public var regular_content_bytes: UInt64
    public var hard_links: Int
    public var symbolic_links: Int
    public var ownership_flags_xattrs_applied = false
    public var bootable_filesystem_claimed = false
}

public func hashFile(_ url: URL) throws -> FileRecord {
    let status = try fileStatus(url)
    try require(status.st_mode & S_IFMT == S_IFREG, "Expected regular file: \(url.path)")
    let stream = try FileHandle(forReadingFrom: url)
    defer { try? stream.close() }
    var hash = SHA256()
    var size: UInt64 = 0
    while let block = try stream.read(upToCount: 4 << 20), !block.isEmpty {
        hash.update(data: block)
        size += UInt64(block.count)
    }
    try require(size == UInt64(status.st_size), "File changed while hashing: \(url.path)")
    return FileRecord(path: url.path, size: size, sha256: hex(hash.finalize()))
}

func boundedData(_ url: URL, limit: Int) throws -> Data {
    let handle = try FileHandle(forReadingFrom: url)
    defer { try? handle.close() }
    let data = try handle.read(upToCount: limit + 1) ?? Data()
    try require(data.count <= limit, "Input exceeds \(limit) bytes: \(url.path)")
    return data
}
