// swift-tools-version: 5.9
import PackageDescription
let package = Package(
    name: "DarwinVerifiedStorageTests",
    platforms: [.macOS(.v10_15)],
    targets: [
        .target(name: "StorageCore", path: "darwin/flutter_secure_storage_darwin/Sources/flutter_secure_storage_darwin", exclude: ["FlutterSecureStorageDarwinPlugin.swift", "Resources"]),
        .testTarget(name: "StorageCoreTests", dependencies: ["StorageCore"], path: "Tests")
    ]
)
