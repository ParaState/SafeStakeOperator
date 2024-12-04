// This is a stub for determining the build profile, see `build_profile_name`.

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let proto_files = ["./bootnode.proto"];
    let includes = ["./"];
    tonic_build::configure().compile(&proto_files, &includes)?;
    Ok(())
}
