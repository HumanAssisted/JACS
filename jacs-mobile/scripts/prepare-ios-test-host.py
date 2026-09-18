#!/usr/bin/env python3
"""Generate a simulator-only app host for the packaged SDK's XCTest sources.

SwiftPM's hostless xctest process has no application Keychain identity. This
small local Xcode project loads the exact package and tests in an ad-hoc signed
app instead. It needs no developer account, provisioning profile or generator
dependency. Production package settings and sources remain unchanged.
"""

import hashlib
import json
import plistlib
import sys
from pathlib import Path
import xml.etree.ElementTree as ET


IDENTIFIER = "ai.hai.jacs.simulator-tests"
KEYCHAIN_GROUP = "JACSTEST01." + IDENTIFIER


def prepare(stage: Path) -> Path:
    tests = sorted((stage / "Tests/JacsMobilePlatformTests").glob("*.swift"))
    if not (stage / "Package.swift").is_file() or not tests:
        raise SystemExit("Assemble the current iOS package and tests first")
    host = stage / "test-host"
    project = host / "JacsMobileTests.xcodeproj"
    schemes = project / "xcshareddata/xcschemes"
    schemes.mkdir(parents=True, exist_ok=True)
    (host / "Host.swift").write_text('''import UIKit

@main
final class TestHostDelegate: UIResponder, UIApplicationDelegate {
    var window: UIWindow?
    func application(_ application: UIApplication,
                     didFinishLaunchingWithOptions options: [UIApplication.LaunchOptionsKey: Any]?) -> Bool {
        let window = UIWindow(frame: UIScreen.main.bounds)
        window.rootViewController = UIViewController()
        window.makeKeyAndVisible()
        self.window = window
        return true
    }
}
''')
    (host / "Host.entitlements").write_bytes(plistlib.dumps({
        "application-identifier": KEYCHAIN_GROUP,
        "keychain-access-groups": [KEYCHAIN_GROUP],
    }))

    objects = {}

    def obj(label, isa, **fields):
        identifier = hashlib.sha256(label.encode()).hexdigest()[:24].upper()
        objects[identifier] = {"isa": isa, **fields}
        return identifier

    def file(label, path, kind, source="<group>"):
        return obj(label, "PBXFileReference", lastKnownFileType=kind,
                   path=path, sourceTree=source)

    def phase(label, isa, files=()):
        return obj(label, isa, buildActionMask=2147483647, files=list(files),
                   runOnlyForDeploymentPostprocessing=0)

    def configs(label, settings):
        config = obj(label + "-release", "XCBuildConfiguration", name="Release",
                     buildSettings=settings)
        return obj(label + "-configs", "XCConfigurationList",
                   buildConfigurations=[config], defaultConfigurationIsVisible=0,
                   defaultConfigurationName="Release")

    host_file = file("host-source", "Host.swift", "sourcecode.swift")
    test_files = [file("test-" + test.name, "../Tests/JacsMobilePlatformTests/" + test.name,
                       "sourcecode.swift") for test in tests]
    app_product = file("host-product", "JacsMobileTestHost.app", "wrapper.application", "BUILT_PRODUCTS_DIR")
    test_product = file("test-product", "JacsMobilePlatformTests.xctest", "wrapper.cfbundle", "BUILT_PRODUCTS_DIR")
    products = obj("products", "PBXGroup", children=[app_product, test_product],
                   name="Products", sourceTree="<group>")
    root_group = obj("root-group", "PBXGroup", children=[host_file, *test_files, products],
                     sourceTree="<group>")
    package = obj("local-package", "XCLocalSwiftPackageReference", relativePath="..")
    sdk = obj("sdk-product", "XCSwiftPackageProductDependency", package=package,
              productName="JacsMobile")
    sdk_build = obj("sdk-framework", "PBXBuildFile", productRef=sdk)

    project_settings = {
        "SDKROOT": "iphonesimulator", "SUPPORTED_PLATFORMS": "iphonesimulator",
        "IPHONEOS_DEPLOYMENT_TARGET": "13.0", "SWIFT_VERSION": "5.0",
        "ENABLE_TESTABILITY": "YES", "SWIFT_OPTIMIZATION_LEVEL": "-O",
        "CLANG_ENABLE_MODULES": "YES", "CODE_SIGN_STYLE": "Manual",
        "CODE_SIGN_IDENTITY": "-", "CODE_SIGNING_ALLOWED": "YES",
        "GENERATE_INFOPLIST_FILE": "YES", "TARGETED_DEVICE_FAMILY": "1,2",
        "CURRENT_PROJECT_VERSION": "1", "MARKETING_VERSION": "1.0",
    }
    app = obj("host-target", "PBXNativeTarget", name="JacsMobileTestHost",
        buildConfigurationList=configs("host", {
            "PRODUCT_BUNDLE_IDENTIFIER": IDENTIFIER, "PRODUCT_NAME": "$(TARGET_NAME)",
            "CODE_SIGN_ENTITLEMENTS": "Host.entitlements",
            "INFOPLIST_KEY_UILaunchScreen_Generation": "YES",
            "LD_RUNPATH_SEARCH_PATHS": "$(inherited) @executable_path/Frameworks",
        }),
        buildPhases=[phase("host-sources", "PBXSourcesBuildPhase", [
            obj("host-compile", "PBXBuildFile", fileRef=host_file)]),
            phase("host-frameworks", "PBXFrameworksBuildPhase")],
        buildRules=[], dependencies=[], productName="JacsMobileTestHost",
        productReference=app_product, productType="com.apple.product-type.application")
    test_target = obj("test-target", "PBXNativeTarget", name="JacsMobilePlatformTests",
        buildConfigurationList=configs("tests", {
            "PRODUCT_BUNDLE_IDENTIFIER": IDENTIFIER + ".tests", "PRODUCT_NAME": "$(TARGET_NAME)",
            "TEST_HOST": "$(BUILT_PRODUCTS_DIR)/JacsMobileTestHost.app/JacsMobileTestHost",
            "BUNDLE_LOADER": "$(TEST_HOST)",
            "LD_RUNPATH_SEARCH_PATHS": "$(inherited) @executable_path/Frameworks @loader_path/Frameworks",
        }),
        buildPhases=[phase("test-sources", "PBXSourcesBuildPhase", [
            obj("compile-" + ref, "PBXBuildFile", fileRef=ref) for ref in test_files]),
            phase("test-frameworks", "PBXFrameworksBuildPhase", [sdk_build])],
        buildRules=[], dependencies=[obj("host-dependency", "PBXTargetDependency", target=app)],
        packageProductDependencies=[sdk], productName="JacsMobilePlatformTests",
        productReference=test_product, productType="com.apple.product-type.bundle.unit-test")
    project_id = obj("project", "PBXProject", buildConfigurationList=configs("project", project_settings),
        attributes={"LastUpgradeCheck": "1540", "TargetAttributes": {
            test_target: {"TestTargetID": app}}},
        compatibilityVersion="Xcode 14.0", developmentRegion="en", knownRegions=["en", "Base"],
        mainGroup=root_group, productRefGroup=products, projectDirPath="", projectRoot="",
        packageReferences=[package], targets=[app, test_target])

    def openstep(value):
        if isinstance(value, dict):
            return "{\n" + "\n".join(f"{json.dumps(k)} = {openstep(v)};" for k, v in value.items()) + "\n}"
        if isinstance(value, list):
            return "(" + ", ".join(openstep(v) for v in value) + ")"
        return json.dumps(value)

    (project / "project.pbxproj").write_text("// !$*UTF8*$!\n" + openstep({
        "archiveVersion": 1, "classes": {}, "objectVersion": 56,
        "objects": objects, "rootObject": project_id,
    }) + "\n")

    scheme = ET.Element("Scheme", LastUpgradeVersion="1540", version="1.3")
    build = ET.SubElement(scheme, "BuildAction", parallelizeBuildables="YES", buildImplicitDependencies="YES")
    entries = ET.SubElement(build, "BuildActionEntries")

    def reference(parent, target, name, product):
        ET.SubElement(parent, "BuildableReference", BuildableIdentifier="primary",
            BlueprintIdentifier=target, BuildableName=product, BlueprintName=name,
            ReferencedContainer="container:JacsMobileTests.xcodeproj")

    for target, name, product in [(app, "JacsMobileTestHost", "JacsMobileTestHost.app"),
                                   (test_target, "JacsMobilePlatformTests", "JacsMobilePlatformTests.xctest")]:
        entry = ET.SubElement(entries, "BuildActionEntry", buildForTesting="YES",
            buildForRunning="NO", buildForProfiling="NO", buildForArchiving="NO", buildForAnalyzing="YES")
        reference(entry, target, name, product)
    test_action = ET.SubElement(scheme, "TestAction", buildConfiguration="Release",
        selectedDebuggerIdentifier="Xcode.DebuggerFoundation.Debugger.LLDB",
        selectedLauncherIdentifier="Xcode.IDEFoundation.Launcher.LLDB", shouldUseLaunchSchemeArgsEnv="YES")
    testable = ET.SubElement(ET.SubElement(test_action, "Testables"), "TestableReference", skipped="NO")
    reference(testable, test_target, "JacsMobilePlatformTests", "JacsMobilePlatformTests.xctest")
    ET.ElementTree(scheme).write(schemes / "JacsMobileTests.xcscheme", encoding="utf-8", xml_declaration=True)
    return project


if __name__ == "__main__":
    if len(sys.argv) != 2:
        raise SystemExit("Usage: prepare-ios-test-host.py <assembled-package-directory>")
    print(prepare(Path(sys.argv[1]).resolve()))
