//
//  BinaryInspection.swift
//  HomeView-firmware
//
//  Created by Phineas Guo on 2026/11/01.
//

import Compression
import Foundation

struct BinaryReader {
    let bytes: [UInt8]
    init(_ data: Data) { bytes = Array(data) }
    var count: Int { bytes.count }
    func range(_ offset: Int, _ length: Int) throws -> Range<Int> {
        try require(offset >= 0 && length >= 0 && offset <= count && length <= count - offset, "Binary field outside input")
        return offset..<(offset + length)
    }
    func u16(_ offset: Int) throws -> UInt16 { try UInt16(u64(offset, width: 2)) }
    func u32(_ offset: Int) throws -> UInt32 { try UInt32(u64(offset, width: 4)) }
    func u64(_ offset: Int, width: Int = 8) throws -> UInt64 {
        let r = try range(offset, width)
        return r.enumerated().reduce(0) { $0 | UInt64(bytes[$1.element]) << ($1.offset * 8) }
    }
    func string(_ offset: Int, _ size: Int) throws -> String {
        let r = try range(offset, size)
        return String(decoding: bytes[r].prefix(while: { $0 != 0 }), as: UTF8.self)
    }
}

public enum FirmwareInspection {
    public static func im4p(_ data: Data) throws -> (type: String, payload: Data) {
        let bytes = Array(data)
        func item(_ cursor: inout Int, end: Int) throws -> (UInt8, Range<Int>) {
            try require(cursor >= 0 && end <= bytes.count && cursor + 2 <= end, "Truncated DER item")
            let tag = bytes[cursor]
            let first = Int(bytes[cursor + 1])
            cursor += 2
            var size = first
            if first & 0x80 != 0 {
                let count = first & 0x7f
                try require(count > 0 && count <= 4 && count <= end - cursor, "Unsupported DER length")
                size = 0
                for _ in 0..<count { size = (size << 8) | Int(bytes[cursor]); cursor += 1 }
            }
            try require(size <= end - cursor, "DER payload outside container")
            let range = cursor..<(cursor + size)
            cursor += size
            return (tag, range)
        }
        var cursor = 0
        let outer = try item(&cursor, end: bytes.count)
        try require(outer.0 == 0x30 && cursor == bytes.count, "Expected one IM4P DER sequence")
        cursor = outer.1.lowerBound
        let magic = try item(&cursor, end: outer.1.upperBound)
        let kind = try item(&cursor, end: outer.1.upperBound)
        let description = try item(&cursor, end: outer.1.upperBound)
        let payload = try item(&cursor, end: outer.1.upperBound)
        try require(magic.0 == 0x16 && String(decoding: bytes[magic.1], as: UTF8.self) == "IM4P"
                    && kind.0 == 0x16 && kind.1.count == 4 && description.0 == 0x16 && payload.0 == 4,
                    "Unsupported IM4P fields")
        return (String(decoding: bytes[kind.1], as: UTF8.self), Data(bytes[payload.1]))
    }

    public static func decodeIM4P(input: URL, output: URL, maximumBytes: Int) throws {
        try require(maximumBytes > 0 && maximumBytes <= 256 << 20, "Invalid decode bound")
        let container = try boundedData(input, limit: 256 << 20)
        let parsed = try im4p(container)
        let payload: Data
        if parsed.payload.starts(with: [0x62, 0x76, 0x78, 0x32]) {
            var capacity = min(1 << 20, maximumBytes)
            var decoded: Data?
            while true {
                var buffer = [UInt8](repeating: 0, count: capacity)
                let size = parsed.payload.withUnsafeBytes { source in
                    buffer.withUnsafeMutableBytes { destination in
                        compression_decode_buffer(destination.bindMemory(to: UInt8.self).baseAddress!, capacity,
                                                  source.bindMemory(to: UInt8.self).baseAddress!, source.count,
                                                  nil, COMPRESSION_LZFSE)
                    }
                }
                if size > 0 && size < capacity { decoded = Data(buffer.prefix(size)); break }
                try require(capacity < maximumBytes, "LZFSE decode failed or output reached the configured bound")
                capacity = min(capacity * 2, maximumBytes)
            }
            payload = decoded!
        } else {
            try require(parsed.payload.count <= maximumBytes, "IM4P payload exceeds bound")
            payload = parsed.payload
        }
        try payload.write(to: output, options: .withoutOverwriting)
    }

    public static func deviceTree(input: URL, output: URL) throws {
        let data = try boundedData(input, limit: 4 << 20)
        let reader = BinaryReader(data)
        var cursor = 0
        var nodes = 0
        struct Node: Encodable {
            var path: String
            var properties: [String: String]
        }
        var records: [Node] = []
        func walk(parent: String, depth: Int) throws {
            try require(depth < 128 && nodes < 100_000, "Device-tree limit exceeded")
            nodes += 1
            let propertyCount = Int(try reader.u32(cursor))
            let childCount = Int(try reader.u32(cursor + 4))
            cursor += 8
            try require(propertyCount <= 100_000 && childCount <= 100_000, "Invalid device-tree counts")
            var properties: [String: String] = [:]
            for _ in 0..<propertyCount {
                let name = try reader.string(cursor, 32)
                let length = Int(try reader.u32(cursor + 32) & 0x7fffffff)
                cursor += 36
                let range = try reader.range(cursor, length)
                let value = Data(reader.bytes[range])
                try require(properties[name] == nil, "Duplicate device-tree property")
                if value.allSatisfy({ $0 == 0 || (32...126).contains($0) }) {
                    properties[name] = String(decoding: value, as: UTF8.self).replacingOccurrences(of: "\0", with: " ").trimmingCharacters(in: .whitespaces)
                } else { properties[name] = "hex:" + hex(value) }
                cursor += (length + 3) & ~3
                _ = try reader.range(cursor, 0)
            }
            let name = properties["name"] ?? "<unnamed>"
            let path = parent.isEmpty ? "/" : (parent == "/" ? "/" + name : parent + "/" + name)
            records.append(Node(path: path, properties: properties))
            for _ in 0..<childCount { try walk(parent: path, depth: depth + 1) }
        }
        try walk(parent: "", depth: 0)
        try require(cursor == data.count, "Trailing device-tree bytes")
        try writeJSON(records, to: output)
    }

    public static func macho(input: URL, output: URL) throws {
        let data = try boundedData(input, limit: 256 << 20)
        let reader = BinaryReader(data)
        struct Segment: Encodable {
            var name: String
            var vmAddress: UInt64
            var vmSize: UInt64
            var fileOffset: UInt64
            var fileSize: UInt64
        }
        struct Image: Encodable {
            var name: String
            var headerOffset: Int
            var cpuType: UInt32
            var cpuSubtype: UInt32
            var fileType: UInt32
            var segments: [Segment]
        }
        var images: [Image] = []
        var queue: [(String, Int)] = [("outer", 0)]
        while !queue.isEmpty {
            let (name, offset) = queue.removeFirst()
            try require(images.count < 4096, "Fileset image limit exceeded")
            try require(try reader.u32(offset) == 0xfeedfacf, "Expected little-endian Mach-O64")
            let count = Int(try reader.u32(offset + 16))
            let size = Int(try reader.u32(offset + 20))
            var cursor = offset + 32
            _ = try reader.range(cursor, size)
            let end = cursor + size
            try require(count <= size / 8, "Invalid Mach-O command count")
            var segments: [Segment] = []
            for _ in 0..<count {
                let command = try reader.u32(cursor)
                let length = Int(try reader.u32(cursor + 4))
                try require(length >= 8 && length % 8 == 0 && length <= end - cursor, "Invalid load command")
                if command == 0x19 {
                    try require(length >= 72, "Truncated segment")
                    let sections = Int(try reader.u32(cursor + 64))
                    try require(length == 72 + sections * 80, "Invalid section array")
                    let off = try reader.u64(cursor + 40)
                    let fileSize = try reader.u64(cursor + 48)
                    try require(off <= data.count && fileSize <= UInt64(data.count) - off, "Segment outside file")
                    segments.append(Segment(name: try reader.string(cursor + 8, 16), vmAddress: try reader.u64(cursor + 24),
                                            vmSize: try reader.u64(cursor + 32), fileOffset: off, fileSize: fileSize))
                } else if command == 0x80000035 && offset == 0 {
                    try require(length >= 32, "Truncated fileset entry")
                    let off = try reader.u64(cursor + 16)
                    let stringOffset = Int(try reader.u32(cursor + 24))
                    try require(off <= data.count && stringOffset >= 32 && stringOffset < length, "Invalid fileset entry")
                    queue.append((try reader.string(cursor + stringOffset, length - stringOffset), Int(off)))
                }
                cursor += length
            }
            try require(cursor == end, "Mach-O command length mismatch")
            images.append(Image(name: name, headerOffset: offset, cpuType: try reader.u32(offset + 4),
                                cpuSubtype: try reader.u32(offset + 8), fileType: try reader.u32(offset + 12), segments: segments))
        }
        try writeJSON(images, to: output)
    }
}
