use sp1_helper::{build_program, build_program_with_args, BuildArgs};

fn main() {
    let args = BuildArgs {
        ignore_rust_version: true,
        elf_name: Some("pos-consensus".to_string()),
        // output_directory: Some("../elf".to_string()),
        ..Default::default()
    };
    build_program_with_args("../consensus-proof", args);
}
