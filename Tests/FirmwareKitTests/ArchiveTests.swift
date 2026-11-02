//
//  ArchiveTests.swift
//  HomeView-firmware
//
//  Created by Phineas Guo on 2026/11/01.
//

import AppleArchive
import CryptoKit
import Darwin
import Foundation
import System
import Testing
@testable import FirmwareKit

struct TemporaryFolder {
    let url: URL
    init() throws {
        url = FileManager.default.temporaryDirectory.appendingPathComponent("homeview-test-" + UUID().uuidString)
        try FileManager.default.createDirectory(at: url, withIntermediateDirectories: true)
    }
    func remove() { try? FileManager.default.removeItem(at: url) }
}

func archiveFile(_ url: URL, compressed: Bool = false, entries: [(String, UInt64, Data, String?)]) throws {
    let file = try #require(ArchiveByteStream.fileStream(path: FilePath(url.path), mode: .writeOnly,
        options: [.create, .exclusiveCreate], permissions: .init(rawValue: 0o600)))
    let bytes = compressed ? try #require(ArchiveByteStream.compressionStream(using: .lzfse, writingTo: file)) : file
    let stream = try #require(ArchiveStream.encodeStream(writingTo: bytes))
    for (path, type, data, link) in entries {
        let header = ArchiveHeader()
        header.append(.uint(key: .init("TYP"), value: type))
        header.append(.string(key: .init("PAT"), value: path))
        if let link { header.append(.string(key: .init("LNK"), value: link)) }
        if type == 70 { header.append(.blob(key: .init("DAT"), size: UInt64(data.count))) }
        try stream.writeHeader(header)
        if type == 70 { try data.withUnsafeBytes { try stream.writeBlob(key: .init("DAT"), from: $0) } }
    }
    try stream.close()
    if compressed { try bytes.close() }
    try file.close()
}

func encryptedFixture(_ root: URL, path: String = "AssetData/payloadv2/payload_chunks.txt") throws -> (URL, Data) {
    let nested = root.appendingPathComponent("nested.aa")
    try archiveFile(nested, entries: [(path, 70, Data("0:123\n".utf8), nil),
        ("AssetData/payloadv2/links.txt", 70, Data(), nil)])
    let data = try Data(contentsOf: nested)
    let input = root.appendingPathComponent("fixture.aea")
    let file = try #require(ArchiveByteStream.fileStream(path: FilePath(input.path), mode: .writeOnly,
        options: [.create, .exclusiveCreate], permissions: .init(rawValue: 0o600)))
    let key = Data(repeating: 7, count: 32)
    let context = ArchiveEncryptionContext(profile: .hkdf_sha256_aesctr_hmac__symmetric__none, compressionAlgorithm: .lzfse)
    try context.setSymmetricKey(SymmetricKey(data: key))
    let encrypted = try #require(ArchiveByteStream.encryptionStream(writingTo: file, encryptionContext: context))
    let stream = try #require(ArchiveStream.encodeStream(writingTo: encrypted))
    let header = ArchiveHeader()
    header.append(.uint(key: .init("TYP"), value: 77))
    header.append(.uint(key: .init("YOP"), value: 69))
    header.append(.blob(key: .init("DAT"), size: UInt64(data.count)))
    try stream.writeHeader(header)
    try data.withUnsafeBytes { try stream.writeBlob(key: .init("DAT"), from: $0) }
    try stream.close()
    try encrypted.close()
    try file.close()
    return (input, key)
}

@Test func encryptedNestedArchiveAndNoOverwrite() throws {
    let tmp = try TemporaryFolder()
    defer { tmp.remove() }
    let (input, key) = try encryptedFixture(tmp.url)
    let output = tmp.url.appendingPathComponent("out")
    let ledger = try OTAExtractor.extract(input: input, output: output, key: key, mode: .index)
    #expect(ledger.regular_files.count == 2)
    #expect(ledger.content_bytes == 6)
    #expect(try FirmwareVerification.verify(root: output, ledger: output.appendingPathComponent("EXTRACTION_COMPLETE.json")) == 2)
    #expect(throws: (any Error).self) { try OTAExtractor.extract(input: input, output: output, key: key, mode: .index) }
}

@Test func wrongKeyDoesNotProduceCompletionLedger() throws {
    let tmp = try TemporaryFolder()
    defer { tmp.remove() }
    let (input, _) = try encryptedFixture(tmp.url)
    let output = tmp.url.appendingPathComponent("out")
    #expect(throws: (any Error).self) {
        try OTAExtractor.extract(input: input, output: output, key: Data(repeating: 9, count: 32), mode: .index)
    }
    #expect(!pathExists(output.appendingPathComponent("EXTRACTION_COMPLETE.json")))
}

@Test func archiveTraversalRejected() throws {
    let tmp = try TemporaryFolder()
    defer { tmp.remove() }
    let (input, key) = try encryptedFixture(tmp.url, path: "../escape")
    #expect(throws: (any Error).self) {
        try OTAExtractor.extract(input: input, output: tmp.url.appendingPathComponent("out"), key: key, mode: .all)
    }
    #expect(!pathExists(tmp.url.appendingPathComponent("escape")))
}

@Test func payloadInventoryExpansionLinksAndTamperDetection() throws {
    let tmp = try TemporaryFolder()
    defer { tmp.remove() }
    let ota = tmp.url.appendingPathComponent("ota")
    let payload = ota.appendingPathComponent("AssetData/payloadv2")
    try FileManager.default.createDirectory(at: payload, withIntermediateDirectories: true)
    try Data("0:999\n".utf8).write(to: payload.appendingPathComponent("payload_chunks.txt"))
    let links = payload.appendingPathComponent("links.txt")
    try Data("=usr/bin/tool\n+usr/bin/copy\n".utf8).write(to: links)
    try archiveFile(payload.appendingPathComponent("payload.000"), compressed: true, entries: [
        ("", 68, Data(), nil), ("usr", 68, Data(), nil), ("usr/bin", 68, Data(), nil),
        ("usr/bin/tool", 70, Data("hello".utf8), nil),
        ("usr/bin/guest", 76, Data(), "/private/guest-absolute")])
    let inventoryDirectory = tmp.url.appendingPathComponent("inventory")
    let inventory = try PayloadTools.inventory(ota: ota, output: inventoryDirectory, selection: .none)
    #expect(inventory.entries.count == 5)
    #expect(inventory.extracted.isEmpty)
    let inventoryURL = inventoryDirectory.appendingPathComponent("inventory.json")
    let root = tmp.url.appendingPathComponent("root")
    let ledger = try PayloadTools.expand(ota: ota, inventory: inventoryURL, output: root)
    #expect(ledger.hard_links == 1 && ledger.symbolic_links == 1)
    #expect(!ledger.bootable_filesystem_claimed)
    let a = try fileStatus(root.appendingPathComponent("usr/bin/tool"))
    let b = try fileStatus(root.appendingPathComponent("usr/bin/copy"))
    #expect(a.st_ino == b.st_ino)
    #expect(try FileManager.default.destinationOfSymbolicLink(atPath: root.appendingPathComponent("usr/bin/guest").path) == "/private/guest-absolute")
    let ledgerURL = tmp.url.appendingPathComponent("root.expansion.json")
    #expect(try FirmwareVerification.verify(root: root, ledger: ledgerURL, inventory: inventoryURL, links: links) == 1)
    try Data("wrong".utf8).write(to: root.appendingPathComponent("usr/bin/tool"))
    #expect(throws: FirmwareError.self) {
        try FirmwareVerification.verify(root: root, ledger: ledgerURL, inventory: inventoryURL, links: links)
    }
}

@Test func fixupReaderDoesNotApplyMetadata() throws {
    let tmp = try TemporaryFolder()
    defer { tmp.remove() }
    let input = tmp.url.appendingPathComponent("fixup.manifest")
    let output = tmp.url.appendingPathComponent("fixup.json")
    try archiveFile(input, compressed: true, entries: [("usr/file", 70, Data(), nil)])
    #expect(try PayloadTools.fixup(input: input, output: output) == 1)
    let rows = try readJSON([EntryRecord].self, from: output)
    #expect(rows[0].path == "usr/file")
    #expect(!pathExists(tmp.url.appendingPathComponent("usr/file")))
}

@Test(arguments: ["../x", "/etc/passwd", "a/../b", "a//b", "a/./b", "x\0y"])
func rejectsUnsafePaths(_ path: String) {
    #expect(throws: FirmwareError.self) { try canonicalPath(path) }
}

@Test func malformedIndicesAndSymlinkParentsRejected() throws {
    #expect(try PayloadTools.chunkIndices("0:123\n1:456\n") == [0, 1])
    #expect(throws: FirmwareError.self) { try PayloadTools.chunkIndices("1:123\n") }
    #expect(throws: FirmwareError.self) { try PayloadTools.chunkIndices("") }
    let symlink = EntryRecord(path: "dir", type: 76, link: "/tmp")
    let file = EntryRecord(path: "dir/file", type: 70, size: 1)
    #expect(throws: FirmwareError.self) { try LinkPlan(entries: [symlink, file], linkText: "") }
    #expect(throws: FirmwareError.self) { try LinkPlan(entries: [file, file], linkText: "") }
}
