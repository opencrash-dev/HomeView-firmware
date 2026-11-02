//
//  InspectionTests.swift
//  HomeView-firmware
//
//  Created by Phineas Guo on 2026/11/01.
//

import Foundation
import Testing
@testable import FirmwareKit

@Test func strictDERParsing() throws {
    // SEQUENCE { IA5String IM4P, IA5String krnl, IA5String "", OCTET STRING abc }
    let data = Data([0x30, 19, 0x16, 4] + Array("IM4P".utf8) + [0x16, 4] + Array("krnl".utf8)
                    + [0x16, 0, 4, 3] + Array("abc".utf8))
    let parsed = try FirmwareInspection.im4p(data)
    #expect(parsed.type == "krnl")
    #expect(parsed.payload == Data("abc".utf8))
    #expect(throws: FirmwareError.self) { try FirmwareInspection.im4p(data.dropLast()) }
    #expect(throws: FirmwareError.self) { try FirmwareInspection.im4p(Data([0x30, 0x80])) }
    #expect(throws: FirmwareError.self) { try FirmwareInspection.im4p(data + Data([0])) }
}

@Test func binaryReaderBoundsAndUnalignedFields() throws {
    let reader = BinaryReader(Data([0, 0x78, 0x56, 0x34, 0x12]))
    #expect(try reader.u32(1) == 0x12345678)
    #expect(throws: FirmwareError.self) { try reader.u64(1) }
    #expect(throws: FirmwareError.self) { try reader.range(-1, 2) }
    #expect(throws: FirmwareError.self) { try reader.range(Int.max, 2) }
}

@Test func truncatedMachOAndTreeRejected() throws {
    let tmp = try TemporaryFolder()
    defer { tmp.remove() }
    let input = tmp.url.appendingPathComponent("bad.bin")
    try Data([0xcf, 0xfa, 0xed, 0xfe]).write(to: input)
    #expect(throws: FirmwareError.self) { try FirmwareInspection.macho(input: input, output: tmp.url.appendingPathComponent("macho.json")) }
    #expect(throws: FirmwareError.self) { try FirmwareInspection.deviceTree(input: input, output: tmp.url.appendingPathComponent("tree.json")) }
}
