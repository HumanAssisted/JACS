// swift-tools-version: 5.9
import PackageDescription

let package = Package(
    name: "JacsMobile",
    platforms: [.iOS(.v13)],
    products: [
        .library(name: "JacsMobile", targets: ["JacsMobile", "JacsMobilePlatform"])
    ],
    targets: [
        .binaryTarget(name: "JacsMobileFFI", path: "JacsMobileFFI.xcframework"),
        .target(
            name: "JacsMobile",
            dependencies: ["JacsMobileFFI"],
            linkerSettings: [
                .linkedFramework("Security"),
                .linkedFramework("SystemConfiguration"),
                .linkedLibrary("resolv")
            ]
        ),
        .target(
            name: "JacsMobilePlatform",
            dependencies: ["JacsMobile"],
            linkerSettings: [
                .linkedFramework("Security"),
                .linkedFramework("LocalAuthentication"),
                .linkedFramework("CryptoKit")
            ]
        )
    ]
)
