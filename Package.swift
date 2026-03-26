// swift-tools-version: 6.0
import PackageDescription

let package = Package(
    name: "bioenv",
    platforms: [.macOS(.v14)],
    targets: [
        .executableTarget(
            name: "bioenv",
            path: "Sources/bioenv",
            linkerSettings: [
                .linkedFramework("Security"),
                .linkedFramework("LocalAuthentication"),
            ]
        ),
    ]
)
