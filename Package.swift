// swift-tools-version: 6.0
import PackageDescription

let package = Package(
    name: "ufo",
    platforms: [
        .macOS(.v14)
    ],
    products: [
        .library(name: "UFOLib", targets: ["UFOLib"]),
        .executable(name: "ufo", targets: ["ufo"]),
        .executable(name: "ufo-fuzz", targets: ["ufo-fuzz"])
    ],
    dependencies: [
        .package(url: "https://github.com/swiftlang/swift-testing.git", from: "0.10.0")
    ],
    targets: [
        .target(
            name: "UFOLib"
        ),
        .executableTarget(
            name: "ufo",
            dependencies: ["UFOLib"]
        ),
        .executableTarget(
            name: "ufo-fuzz",
            dependencies: ["UFOLib"]
        ),
        .testTarget(
            name: "UFOLibTests",
            dependencies: [
                "UFOLib",
                "ufo",
                .product(name: "Testing", package: "swift-testing")
            ]
        )
    ]
)
