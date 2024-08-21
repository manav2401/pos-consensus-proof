extern crate prost_build;

fn main() {
    println!("hello from build.rs");
    prost_build::compile_protos(&["src/milestone.proto"], &["src/"]).unwrap();
}
