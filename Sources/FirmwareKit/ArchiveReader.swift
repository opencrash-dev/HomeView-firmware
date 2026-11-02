//
//  ArchiveReader.swift
//  HomeView-firmware
//
//  Created by Phineas Guo on 2026/11/01.
//
// Segment adapter adapted from Lakr233/vphone-cli, commit 57bbc93c.
// Copyright (c) 2026 @Lakr233. MIT; see THIRD_PARTY_NOTICES.md.

import AppleArchive
import CryptoKit
import Foundation
import System

final class BlobSegment: ArchiveByteStreamProtocol {
    let parent: ArchiveStream
    var remaining: UInt64

    init(parent: ArchiveStream, count: UInt64) {
        self.parent = parent
        remaining = count
    }

    func read(into buffer: UnsafeMutableRawBufferPointer) throws -> Int {
        let count = Int(min(UInt64(buffer.count), remaining))
        guard count > 0 else { return 0 }
        try parent.readBlob(key: ArchiveHeader.FieldKey("DAT"), into: .init(rebasing: buffer[..<count]))
        remaining -= UInt64(count)
        return count
    }

    func read(into: UnsafeMutableRawBufferPointer, atOffset: Int64) throws -> Int { throw Errno.notSupported }
    func write(from: UnsafeRawBufferPointer) throws -> Int { throw Errno.notSupported }
    func write(from: UnsafeRawBufferPointer, atOffset: Int64) throws -> Int { throw Errno.notSupported }
    func seek(toOffset: Int64, relativeTo: FileDescriptor.SeekOrigin) throws -> Int64 { throw Errno.notSupported }
    func cancel() {}
    func close() throws {}
}

extension ArchiveHeader {
    func number(_ key: String) -> UInt64? {
        if case let .uint(_, value)? = field(forKey: FieldKey(key)) { return value }
        return nil
    }
    func string(_ key: String) -> String? {
        if case let .string(_, value)? = field(forKey: FieldKey(key)) { return value }
        return nil
    }
    var blobSize: UInt64 {
        if case let .blob(_, size, _)? = field(forKey: FieldKey("DAT")) { return size }
        return 0
    }
    func record(chunk: String? = nil) throws -> EntryRecord? {
        guard let original = string("PAT"), let type = number("TYP") else { return nil }
        return EntryRecord(path: try canonicalPath(original), type: type, size: blobSize, chunk: chunk,
                           link: string("LNK"), UID: number("UID"), GID: number("GID"),
                           MOD: number("MOD"), FLG: number("FLG"))
    }
}

enum ArchiveReader {
    static func encrypted<T>(_ input: URL, key: Data, body: (ArchiveStream) throws -> T) throws -> T {
        try require(key.count == 32, "The AEA key must decode to exactly 32 bytes")
        guard let file = ArchiveByteStream.fileStream(path: FilePath(input.path), mode: .readOnly, options: [], permissions: .init(rawValue: 0o644)),
              let context = ArchiveEncryptionContext(from: file) else {
            throw FirmwareError("Cannot open AEA encryption context")
        }
        defer { try? file.close() }
        try context.setSymmetricKey(SymmetricKey(data: key))
        guard let plain = ArchiveByteStream.decryptionStream(readingFrom: file, encryptionContext: context),
              let archive = ArchiveStream.decodeStream(readingFrom: plain) else {
            throw FirmwareError("Cannot decode encrypted Apple Archive")
        }
        defer { try? archive.close(); try? plain.close() }
        return try withExtendedLifetime((file, context, plain)) {
            let result = try body(archive)
            try archive.close()
            try plain.close()
            return result
        }
    }

    static func compressed<T>(_ input: URL, body: (ArchiveStream) throws -> T) throws -> T {
        guard let file = ArchiveByteStream.fileStream(path: FilePath(input.path), mode: .readOnly, options: [], permissions: .init(rawValue: 0o644)),
              let decoded = ArchiveByteStream.decompressionStream(readingFrom: file),
              let archive = ArchiveStream.decodeStream(readingFrom: decoded) else {
            throw FirmwareError("Cannot open compressed payload: \(input.path)")
        }
        defer { try? archive.close(); try? decoded.close(); try? file.close() }
        return try withExtendedLifetime((file, decoded)) {
            let result = try body(archive)
            try archive.close()
            try decoded.close()
            return result
        }
    }

    static func nested<T>(_ parent: ArchiveStream, size: UInt64, compressed: Bool = false,
                          body: (ArchiveStream) throws -> T) throws -> T {
        let segment = BlobSegment(parent: parent, count: size)
        guard let bytes = ArchiveByteStream.customStream(instance: segment) else {
            throw FirmwareError("Cannot open archive segment")
        }
        defer { try? bytes.close() }
        let decoded = compressed ? ArchiveByteStream.decompressionStream(readingFrom: bytes) : bytes
        guard let decoded, let archive = ArchiveStream.decodeStream(readingFrom: decoded) else {
            throw FirmwareError("Cannot decode archive segment")
        }
        defer { try? archive.close(); if compressed { try? decoded.close() } }
        return try withExtendedLifetime((segment, bytes, decoded)) {
            let result = try body(archive)
            try archive.close()
            if compressed { try decoded.close() }
            return result
        }
    }

    static func walk(_ stream: ArchiveStream, depth: Int = 0,
                     body: (ArchiveHeader, ArchiveStream) throws -> Void) throws {
        try require(depth < 16, "Archive nesting limit exceeded")
        while let header = try stream.readHeader() {
            if header.number("YOP") == 69 {
                try nested(stream, size: header.blobSize) { try walk($0, depth: depth + 1, body: body) }
            } else {
                try body(header, stream)
            }
        }
    }

    static func writeBlob(_ stream: ArchiveStream, size: UInt64, to output: URL, path: String) throws -> FileRecord {
        try FileManager.default.createDirectory(at: output.deletingLastPathComponent(), withIntermediateDirectories: true)
        let descriptor = try FileDescriptor.open(FilePath(output.path), .writeOnly,
                                                options: [.create, .exclusiveCreate], permissions: .init(rawValue: 0o600))
        defer { try? descriptor.close() }
        var remaining = size
        var buffer = [UInt8](repeating: 0, count: 4 << 20)
        var hash = SHA256()
        while remaining > 0 {
            let count = Int(min(UInt64(buffer.count), remaining))
            try buffer.withUnsafeMutableBytes { raw in
                let slice = UnsafeMutableRawBufferPointer(rebasing: raw[..<count])
                try stream.readBlob(key: ArchiveHeader.FieldKey("DAT"), into: slice)
                try descriptor.writeAll(UnsafeRawBufferPointer(slice))
                hash.update(bufferPointer: UnsafeRawBufferPointer(slice))
            }
            remaining -= UInt64(count)
        }
        return FileRecord(path: path, size: size, sha256: hex(hash.finalize()))
    }
}
