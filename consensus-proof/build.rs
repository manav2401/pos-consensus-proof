extern crate prost_build;

fn main() {
    prost_build::compile_protos(&["src/types.proto"], &["src/"]).unwrap();
}
