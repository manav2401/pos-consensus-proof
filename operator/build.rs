use sp1_helper::{build_program_with_args, BuildArgs};

fn main() {
    let args = BuildArgs {
        ignore_rust_version: true,
        output_directory: Some("../elf".to_string()),
        elf_name: Some("pos-consensus-proof".to_string()),
        ..Default::default()
    };
    build_program_with_args("../consensus-proof", args);
}
