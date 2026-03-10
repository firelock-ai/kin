fn main() {
    // KuzuDB's statically-linked extensions need the binary to re-export
    // CXX bridge symbols. On Linux use -rdynamic; on macOS use -exported_symbol
    // patterns that cover the kuzu_rs bridge functions.
    if cfg!(target_os = "linux") {
        println!("cargo:rustc-link-arg=-rdynamic");
    }
    // On macOS the default linking behaviour (no -undefined,dynamic_lookup)
    // combined with -force_load from the kuzu build should suffice.
}
