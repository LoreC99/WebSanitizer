use WebSanitizer::cli::cli::Cli;

#[tokio::main]
async fn main() {
    let args= Cli::parse_args();
    println!("Avvio web sanitizer con input: {:?}", args.inputs);

    println!("=== Avvio Web Sanitizer ===\n");

}
