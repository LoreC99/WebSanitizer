use std::path::PathBuf;
use clap::{Parser, ArgAction};

// #[derive(Parser, Debug)]
// #[command(
//     name = "web-sanitizer",
//     author = "Studente <email@studenti.unibo.it>", // Adatta con i tuoi dati
//     version,
//     about = "Un web sanitizer concorrente e sicuro in Rust",
//     long_about = "Applicazione CLI che analizza, pulisce e neutralizza contenuti web (HTML, URL, asset) \
//                   in base a policy dichiarative, producendo report strutturati in JSON."
// )]
// pub struct Cli {
//     /// Lista di input da elaborare in batch (file locali, directory o URL)
//     #[arg(
//         short = 'i',
//         long = "input",
//         required = true,
//         value_name = "PATH_OR_URL",
//         num_args = 1..
//     )]
//     pub inputs: Vec<String>,
// 
//     /// Directory di destinazione per i file sanitizzati
//     #[arg(
//         short = 'o',
//         long = "output-dir",
//         value_name = "DIR",
//         default_value = "./sanitized_output"
//     )]
//     pub output_dir: PathBuf,
// 
//     /// Percorso del file di configurazione delle policy (es. JSON o TOML)
//     #[arg(
//         short = 'p',
//         long = "policy",
//         value_name = "FILE_PATH"
//     )]
//     pub policy_path: Option<PathBuf>,
// 
//     /// Livello di verbosità dei log (es. -v info, -vv debug, -vvv trace)
//     #[arg(
//         short = 'v',
//         long = "verbose",
//         action = ArgAction::Count
//     )]
//     pub verbosity: u8,
// 
//     /// Budget di dimensione massima (in byte) per singolo file (previene attacchi DoS)
//     #[arg(
//         long = "max-bytes",
//         value_name = "BYTES",
//         default_value = "10485760" // 10 MB default
//     )]
//     pub max_bytes: u64,
// 
//     /// Timeout massimo (in secondi) per l'elaborazione di un singolo input
//     #[arg(
//         long = "timeout",
//         value_name = "SECONDS",
//         default_value = "30"
//     )]
//     pub timeout_seconds: u64,
// }
// 
// impl Cli {
//     /// Estrae ed effettua il parsing degli argomenti da riga di comando
//     pub fn parse_args() -> Self {
//         Self::parse()
//     }
//}