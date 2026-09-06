fn main() {
    if let Err(error) = agentx::run() {
        eprintln!("error: {error:#}");
        std::process::exit(1);
    }
}
