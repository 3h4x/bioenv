// swift-tools-version: 6.0
import PackageDescription

let package = Package(
    name: "bioenv",
    platforms: [.macOS(.v14)],
    targets: [
        .target(
            name: "bioenvLib",
            path: "Sources/bioenvLib",
            linkerSettings: [
                .linkedFramework("Security"),
                .linkedFramework("LocalAuthentication"),
            ]
        ),
        .executableTarget(
            name: "bioenv",
            dependencies: ["bioenvLib"],
            path: "Sources/bioenv"
        ),
        .testTarget(
            name: "bioenvTests",
            dependencies: ["bioenvLib"],
            path: "Tests/bioenvTests"
        ),
    ]
)
