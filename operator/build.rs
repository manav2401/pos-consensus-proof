use sp1_helper::{build_program_with_args, BuildArgs};

fn main() {
    let args = BuildArgs {
        ignore_rust_version: true,
        elf_name: "pos-consensus".to_string(),
        ..Default::default()
    };
    build_program_with_args("../consensus-proof", args);
}
