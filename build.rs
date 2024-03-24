use std::process::Command;

const TRAMPOLINE_ASM_FILE_PATH: &str = "trampoline.asm";

fn main() {
    println!("cargo::rerun-if-changed={}", TRAMPOLINE_ASM_FILE_PATH);

    let out_dir = std::env::var("OUT_DIR").unwrap();
    let trampoline_file_path = format!("{}/trampoline", out_dir);
    let exit_code = Command::new("nasm")
        .args(["-f", "bin", TRAMPOLINE_ASM_FILE_PATH, "-o"])
        .arg(&trampoline_file_path)
        .spawn()
        .unwrap()
        .wait()
        .unwrap();
    assert!(exit_code.success());
}
