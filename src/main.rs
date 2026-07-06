use WebSanitizer::cli::cli::Cli;

fn main() {
    let args= Cli::parse_args();
    println!("Avvio web sanitizer con input: {:?}", args.inputs);
}
