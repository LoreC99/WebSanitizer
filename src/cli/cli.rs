use std::path::PathBuf;
use clap::{Parser};

#[derive(Parser, Debug)]
#[command(
    name = "web-sanitizer",
    author = "Chiara De Rinaldis e Lorenzo Canova",
    version,
    about = "Un web sanitizer concorrente e sicuro in Rust",
    long_about = "Applicazione CLI che analizza, pulisce e neutralizza contenuti web (HTML, URL, asset) \
                  in base a policy dichiarative, producendo report strutturati in JSON"
)]
pub struct Cli {
    /// Lista di input da elaborare in batch (file locali, directory o URL)
    #[arg(
        short = 'i',
        long = "input",
        required = true,
        value_name = "PATH_OR_URL",
        num_args = 1..
    )]
    pub inputs: Vec<String>,

    /// Directory di destinazione per i file sanitizzati
    #[arg(
        short = 'o',
        long = "output-dir",
        value_name = "DIR",
        default_value = "./sanitized_output"
    )]
    pub output_dir: PathBuf,

    /// Percorso del file di configurazione delle policy (es. JSON o TOML)
    #[arg(
        short = 'p',
        long = "policy",
        value_name = "FILE_PATH"
    )]
    pub policy_path: Option<PathBuf>,

    /// Budget di dimensione massima (in byte) per singolo file (previene attacchi DoS)
    #[arg(
        long = "max-bytes",
        value_name = "BYTES",
        default_value = "10485760" // 10 MB default
    )]
    pub max_bytes: u64,

    /// Timeout massimo (in secondi) per l'elaborazione di un singolo input
    #[arg(
        long = "timeout",
        value_name = "SECONDS",
        default_value = "30"
    )]
    pub timeout_seconds: u64,

    /// Numero di thread worker da utilizzare (default: numero di core logici)
    #[arg(
        short = 't',
        long = "threads",
        value_name = "THREADS"
    )]
    pub threads: Option<usize>,

    /// Profondità massima per il download delle sotto-risorse (es. CSS nei CSS)
    #[arg(
        long = "max-depth",
        value_name = "DEPTH",
        default_value = "128"
    )]
    pub max_depth: u8,

    /// Numero massimo di richieste HTTP per singolo input
    #[arg(
        long = "max-requests",
        value_name = "REQUESTS",
        default_value = "50"
    )]
    pub max_requests: u32,

    /// Profondità massima per l'esplorazione delle directory locali
    #[arg(
        long = "dir-max-depth",
        value_name = "DIR_DEPTH",
        default_value = "10"
    )]
    pub dir_max_depth: usize,

    /// Numero massimo di file da scansionare per directory (previene DoS da I/O)
    #[arg(
        long = "dir-max-files",
        value_name = "MAX_FILES",
        default_value = "10000"
    )]
    pub dir_max_files: usize,

    /// Percorso in cui salvare il report JSON globale dell'elaborazione batch
    #[arg(
        short = 'r',
        long = "report-file",
        value_name = "REPORT_PATH",
        default_value = "./sanitizer_report.json"
    )]
    pub report_file: PathBuf,
}

impl Cli {
    /// Estrae ed effettua il parsing degli argomenti da riga di comando
    pub fn parse_args() -> Self {
        Self::parse()
    }
}