plugins {
    id("com.android.library")
    id("org.jetbrains.kotlin.android")
    id("maven-publish")
}

group = "ai.hai"
version = "0.14.0"

android {
    namespace = "ai.hai.jacs"
    compileSdk = 35
    buildToolsVersion = "35.0.0"
    // Matches the existing NDK used by cargo-ndk and prevents AGP selecting a
    // different SDK package while stripping the prebuilt native libraries.
    ndkVersion = "27.3.13750724"
    defaultConfig {
        minSdk = 30
        testInstrumentationRunner = "androidx.test.runner.AndroidJUnitRunner"
        consumerProguardFiles("consumer-rules.pro")
    }
    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }
    kotlinOptions { jvmTarget = "17" }
    // AAR publication metadata carries the JNA runtime dependency.
    publishing { singleVariant("release") { withSourcesJar() } }
}

dependencies {
    // UniFFI's generated Kotlin uses JNA; the Android artifact includes libjnidispatch.
    implementation("net.java.dev.jna:jna:5.18.1@aar")
    androidTestImplementation("androidx.test:runner:1.6.2")
    androidTestImplementation("androidx.test.ext:junit:1.2.1")
}

afterEvaluate {
    publishing {
        publications {
            create<MavenPublication>("release") {
                from(components["release"])
                artifactId = "jacs-mobile"
                pom {
                    name.set("JACS Mobile")
                    description.set("Portable JACS UniFFI bindings and Android Keystore adapters")
                    url.set("https://github.com/HumanAssisted/JACS")
                    licenses { license { name.set("Apache-2.0") } }
                }
            }
        }
        // Local assembly only; publishing to an external repository is a separate action.
        repositories { maven { name = "bundle"; url = uri(layout.buildDirectory.dir("maven")) } }
    }
}
