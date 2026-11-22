// swift-tools-version: 6.0
import PackageDescription

let package = Package(
    name: "SigilCore",
    platforms: [.macOS(.v14)],
    products: [
        .library(name: "SigilCore", targets: ["SigilCore"]),
    ],
    targets: [
        .target(
            name: "SigilCore",
            path: "Sources/SigilCore"
        ),
        .testTarget(
            name: "SigilCoreTests",
            dependencies: ["SigilCore"],
            path: "Tests/SigilCoreTests",
            resources: [.copy("Fixtures")]
        ),
    ],
    swiftLanguageModes: [.v6]
)
