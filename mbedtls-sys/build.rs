extern crate bindgen;
extern crate cc;
extern crate cmake;

use std::env;
use std::path::PathBuf;

use bindgen::builder;

fn main() {
    compile_wrapper();
    compile_mbedtls();
    gen_binding();
}

fn compile_mbedtls() {
    let mut cfg = cmake::Config::new("mbedtls");
    cfg.define("ENABLE_PROGRAMS", "OFF")
        .define("ENABLE_TESTING", "OFF");

    let build_type = match env::var("PROFILE").unwrap().as_ref() {
        "debug" => "Debug",
        "release" => "Release",
        _ => "Debug",
    };

    cfg.build_target("clean").build();

    let dst = cfg.build_target("lib").build();

    println!(
        "cargo:rustc-link-search=native={}/build/library/{}",
        dst.display(),
        build_type
    );
    println!("cargo:rustc-link-lib=mbedtls");
    println!("cargo:rustc-link-lib=mbedx509");
    println!("cargo:rustc-link-lib=mbedcrypto");
}

fn compile_wrapper() {
    cc::Build::new()
        .include("mbedtls/include")
        .file("wrapper.c")
        .compile("wrapper");
}

fn gen_binding() {
    let out_path = PathBuf::from(env::var("OUT_DIR").unwrap());

    let bindings = builder()
        .header("wrapper.h")
        .clang_arg("-Imbedtls/include")
        .generate()
        .expect("bindgen error");

    bindings
        .write_to_file(out_path.join("bindings.rs"))
        .expect("Couldn't write bindings!");
}
