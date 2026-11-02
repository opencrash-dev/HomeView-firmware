//
//  HomeViewFirmware.swift
//  HomeView-firmware
//
//  Created by Phineas Guo on 2026/11/01.
//

import Darwin
import FirmwareKit
import Foundation

@main
struct HomeViewFirmware {
    static let help = """
    homeview-firmware: read-only firmware research and bounded extraction

    Commands:
      extract   --input AEA --output NEW_DIR --mode metadata|kernel|index|all
                [--key-file BASE64_FILE | --key-env ENV_NAME]
      inventory --ota EXTRACTED_OTA --output NEW_DIR [--profile none|startup|additional]
      expand    --ota EXTRACTED_OTA --inventory INVENTORY_JSON --output NEW_DIR
      fixup     --input COMPRESSED_FIXUP --output NEW_JSON
      decode    --input IM4P --output NEW_FILE [--max-mib 256]
      tree      --input DECODED_ADT --output NEW_JSON
      macho     --input MACH_O --output NEW_JSON
      hash      --input REGULAR_FILE
      verify    --root EXTRACTED_ROOT --ledger EXTRACTION_JSON
                [--inventory INVENTORY_JSON --links LINKS_TXT [--fixup FIXUP_JSON]]

    AEA key default: HOMEVIEW_AEA_KEY (Base64, exactly 32 decoded bytes).
    Output files/directories must not already exist. No ownership/xattrs applied.
    Extraction is not a restore, signature verification, or firmware boot.
    """

    static func main() {
        do { try run(Array(CommandLine.arguments.dropFirst())) }
        catch {
            try? FileHandle.standardError.write(contentsOf: Data("Error: \(error)\n".utf8))
            exit(1)
        }
    }

    static func run(_ arguments: [String]) throws {
        guard let command = arguments.first, !["--help", "-h", "help"].contains(command) else {
            print(help)
            return
        }
        if arguments.dropFirst().contains("--help") { print(help); return }
        let allowed: [String: Set<String>] = [
            "extract": ["input", "output", "mode", "key-file", "key-env"],
            "inventory": ["ota", "output", "profile"],
            "expand": ["ota", "inventory", "output"],
            "fixup": ["input", "output"], "decode": ["input", "output", "max-mib"],
            "tree": ["input", "output"], "macho": ["input", "output"],
            "hash": ["input"], "verify": ["root", "ledger", "inventory", "links", "fixup"]
        ]
        guard let keys = allowed[command] else { throw FirmwareError("Unknown command: \(command)") }
        let tail = Array(arguments.dropFirst())
        guard tail.count.isMultiple(of: 2) else { throw FirmwareError("Options require values; use --help") }
        var options: [String: String] = [:]
        for index in stride(from: 0, to: tail.count, by: 2) {
            let key = String(tail[index].dropFirst(2))
            guard tail[index].hasPrefix("--"), keys.contains(key), options[key] == nil,
                  !tail[index + 1].isEmpty else { throw FirmwareError("Unknown, duplicate, or empty option: \(tail[index])") }
            options[key] = tail[index + 1]
        }
        func value(_ name: String) throws -> String {
            guard let value = options[name] else { throw FirmwareError("Missing --\(name)") }
            return value
        }
        func url(_ name: String) throws -> URL { URL(fileURLWithPath: try value(name)) }
        func optionalURL(_ name: String) -> URL? { options[name].map { URL(fileURLWithPath: $0) } }
        switch command {
        case "extract":
            guard let mode = ExtractionMode(rawValue: try value("mode")) else { throw FirmwareError("Unknown extraction mode") }
            guard options["key-file"] == nil || options["key-env"] == nil else { throw FirmwareError("Choose one key source") }
            let encoded: String
            if let path = options["key-file"] {
                let handle = try FileHandle(forReadingFrom: URL(fileURLWithPath: path))
                defer { try? handle.close() }
                let data = try handle.read(upToCount: 4097) ?? Data()
                guard data.count <= 4096 else { throw FirmwareError("Key file is too large") }
                encoded = String(decoding: data, as: UTF8.self)
            } else {
                let name = options["key-env"] ?? "HOMEVIEW_AEA_KEY"
                guard let text = ProcessInfo.processInfo.environment[name] else { throw FirmwareError("Missing key environment variable: \(name)") }
                encoded = text
            }
            guard let key = Data(base64Encoded: encoded.trimmingCharacters(in: .whitespacesAndNewlines)), key.count == 32 else {
                throw FirmwareError("Expected a Base64-encoded 32-byte AEA key")
            }
            let ledger = try OTAExtractor.extract(input: url("input"), output: url("output"), key: key, mode: mode)
            print("Complete: \(ledger.regular_files.count) files, \(ledger.content_bytes) bytes")
        case "inventory":
            guard let profile = SelectionProfile(rawValue: options["profile"] ?? "none") else { throw FirmwareError("Unknown selection profile") }
            let result = try PayloadTools.inventory(ota: url("ota"), output: url("output"), selection: profile)
            print("Complete: \(result.chunks.count) chunks, \(result.entries.count) entries")
        case "expand":
            let result = try PayloadTools.expand(ota: url("ota"), inventory: url("inventory"), output: url("output"))
            print("Complete: \(result.regular_files.count) data files, \(result.hard_links) hard links, \(result.symbolic_links) symlinks")
        case "fixup": print("Read \(try PayloadTools.fixup(input: url("input"), output: url("output"))) fixup records")
        case "decode":
            guard let mib = Int(options["max-mib"] ?? "256"), (1...256).contains(mib) else { throw FirmwareError("--max-mib must be 1...256") }
            try FirmwareInspection.decodeIM4P(input: url("input"), output: url("output"), maximumBytes: mib << 20)
        case "tree": try FirmwareInspection.deviceTree(input: url("input"), output: url("output"))
        case "macho": try FirmwareInspection.macho(input: url("input"), output: url("output"))
        case "hash":
            let result = try hashFile(url("input"))
            print("\(result.sha256)  \(result.path) (\(result.size) bytes)")
        case "verify":
            let count = try FirmwareVerification.verify(root: url("root"), ledger: url("ledger"),
                inventory: optionalURL("inventory"), links: optionalURL("links"), fixup: optionalURL("fixup"))
            print("Verified \(count) regular data files")
        default: throw FirmwareError("Unimplemented command")
        }
    }
}
