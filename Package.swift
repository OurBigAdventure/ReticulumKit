// swift-tools-version: 6.1
import PackageDescription

let package = Package(
    name: "ReticulumKit",
    platforms: [.iOS(.v16), .macOS(.v13)],
    products: [
        .library(name: "ReticulumKit", targets: ["ReticulumKit"]),
    ],
    dependencies: [
        .package(url: "https://github.com/apple/swift-log.git", from: "1.6.0"),
        .package(url: "https://github.com/fumoboy007/msgpack-swift.git", from: "2.0.6"),
    ],
    targets: [
        .target(
            name: "CBZip2",
            publicHeadersPath: "include",
            cSettings: [.headerSearchPath("include")],
            linkerSettings: [.linkedLibrary("bz2")]
        ),
        .target(
            name: "ReticulumKit",
            dependencies: [
                "CBZip2",
                .product(name: "Logging", package: "swift-log"),
                .product(name: "DMMessagePack", package: "msgpack-swift"),
            ]
        ),
        .testTarget(
            name: "ReticulumKitTests",
            dependencies: ["ReticulumKit"],
            resources: [.copy("Fixtures")]
        ),
    ]
)
