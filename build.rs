fn main() {
    println!("cargo:rerun-if-changed=proto/protocol.proto");
    tonic_build::configure()
        .build_client(true)
        .build_server(true)
        .format(true)
        .compile(&["proto/protocol.proto"], &["proto"])
        .unwrap();
}
