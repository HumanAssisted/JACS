fn main() {
    // Tell cargo to generate a pkg-config file
    println!("cargo:rerun-if-changed=build.rs");
}
