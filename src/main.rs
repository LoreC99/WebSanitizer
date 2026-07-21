use std::process;
use std::sync::Arc;

use WebSanitizer::cli::cli::Cli;
use WebSanitizer::config::loader::{default_policy, load_policy};
use WebSanitizer::sanitizer::factory;
use WebSanitizer::parser::html;
use WebSanitizer::report::report::SanitizationReport;

#[tokio::main]
async fn main() {
    let args = Cli::parse_args();
    println!("Avvio web sanitizer con input: {:?}", args.inputs);

    println!("=== Avvio Web Sanitizer ===\n");

    let policy = match &args.policy_path {
        Some(path) => match load_policy(path) {
            Ok(policy) => policy,
            Err(err) => {
                eprintln!("Errore caricando la policy da {}: {}", path.display(), err);
                process::exit(1);
            }
        },
        None => default_policy(),
    };
    /*
    let engine = Arc::new(factory::create_engine(policy.html));

    // 1. leggi l'input
    let root_nodes = parse(&args.inputs).expect("Errore nel parsing dell'input HTML");

    // 2. sanitizza
    let (_sanitized_nodes, actions) = engine.run(root_nodes);

    // 3. crea il report
    let report = SanitizationReport {
        input_source: input_path.to_string(),
        status: "Cleaned".to_string(),
        actions,
    };

    // 4. serializza in JSON
    let json = serde_json::to_string_pretty(&report)?;
    fs::write("report.json", json)?;
    */

}
