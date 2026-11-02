// swift-tools-version: 6.0
//
//  Package.swift
//  HomeView-firmware
//
//  Created by Phineas Guo on 2026/11/01.
//

import PackageDescription

let package = Package(
    name: "HomeView-firmware",
    platforms: [.macOS(.v15)],
    products: [.executable(name: "homeview-firmware", targets: ["HomeViewFirmware"])],
    targets: [
        .target(name: "FirmwareKit"),
        .executableTarget(name: "HomeViewFirmware", dependencies: ["FirmwareKit"]),
        .testTarget(name: "FirmwareKitTests", dependencies: ["FirmwareKit"])
    ]
)
