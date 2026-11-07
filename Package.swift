// swift-tools-version: 5.9
import PackageDescription

let package = Package(
    name: "OSPinOverload",
    platforms: [.macOS(.v13), .iOS(.v15)],
    products: [
        .library(name: "OSPinCore", targets: ["OSPinCore"]),
        .executable(name: "ospin-inspect", targets: ["OSPinInspect"])
    ],
    targets: [
        .target(name: "OSPinCore", linkerSettings: [.linkedLibrary("sqlite3")]),
        .executableTarget(name: "OSPinInspect", dependencies: ["OSPinCore"]),
        .testTarget(name: "OSPinCoreTests", dependencies: ["OSPinCore"])
    ]
)
