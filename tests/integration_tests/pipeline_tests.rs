use std::fs;
use std::path::PathBuf;
use WebSanitizer::config::loader::default_policy;
use WebSanitizer::parser::html::HtmlParser;
use WebSanitizer::sanitizer::engine::SanitizerEngine;
use WebSanitizer::sanitizer::html_rules::{DangerousAttributeRule, TagAllowListRule};
use WebSanitizer::input::directory::DirectoryScanner;
use WebSanitizer::report::report::{SanitizationReport, BatchReport};
use serde_json::Value;

use std::collections::HashSet;
use std::sync::atomic::Ordering;
use std::sync::{mpsc, Arc};

use WebSanitizer::cli::cli::Cli;
use WebSanitizer::scheduler::workers::{Job, SharedState, ThreadPool};

fn temp_path(filename: &str) -> PathBuf {
    let mut p = std::env::temp_dir();
    p.push(format!("websanitizer_test_{}", filename));
    p
}

#[test]
//Pipline di test: File Locale HTML → Output Sanitizzato → Report JSON
fn test_integration_file_to_output_and_json_report() {
    let input_file = temp_path("input_infetto.html");
    let output_file = temp_path("output_pulito.html");
    let report_file = temp_path("report_finale.json");

    let raw_html = r#"
        <!DOCTYPE html>
        <html>
            <head>
                <script>alert('xss');</script>
            </head>
            <body>
                <h1 onclick="alert('click')">Titolo Progetto</h1>
                <a href="javascript:alert('link')">Link Pericoloso</a>
            </body>
        </html>
    "#;

    fs::write(&input_file, raw_html).expect("Scrittura input fallita");

    let content = fs::read_to_string(&input_file).expect("Lettura input fallita");

    let policy = default_policy();
    let mut engine = SanitizerEngine::new();
    engine.add_rule(Box::new(TagAllowListRule { config: policy.html.clone() }));
    engine.add_rule(Box::new(DangerousAttributeRule { url_config: policy.url.clone() }));

    let mut parser = HtmlParser::new(&content);
    let dom = parser.parse().expect("Parsing DOM fallito");
    let (sanitized_dom, actions) = engine.run(dom);

    let sanitized_html: String = sanitized_dom
        .iter()
        .map(|n| n.to_html_string())
        .collect();

    fs::write(&output_file, &sanitized_html).expect("Scrittura HTML sanificato fallita");

    // Crezione del report strutturato con i tipi definiti nel progetto
    let report = SanitizationReport {
        input_source: input_file.to_string_lossy().to_string(),
        status: "Cleaned".to_string(),
        actions,
        sanitized_html: sanitized_html.clone(),
    };

    let json_report = serde_json::to_string_pretty(&report).expect("Serializzazione JSON fallita");
    fs::write(&report_file, json_report).expect("Scrittura JSON fallita");

    // Verifiche
    assert!(output_file.exists());
    let saved_html = fs::read_to_string(&output_file).unwrap();
    assert!(!saved_html.contains("<script>"));
    assert!(!saved_html.contains("onclick"));
    assert!(!saved_html.contains("javascript:"));
    assert!(saved_html.contains("Titolo Progetto"));

    assert!(report_file.exists());
    let saved_json_str = fs::read_to_string(&report_file).unwrap();
    let json_val: Value = serde_json::from_str(&saved_json_str).unwrap();

    let json_actions = json_val.get("actions").and_then(|v| v.as_array()).unwrap();
    assert_eq!(json_actions.len(), 3);

    // Cleanup
    let _ = fs::remove_file(input_file);
    let _ = fs::remove_file(output_file);
    let _ = fs::remove_file(report_file);
}

//test per quando input viene fornito come directory contenente più file HTML
#[test]
fn test_integration_directory_batch_scanning_and_sanitization() {
    // Setup cartelle temporanee
    let mut input_dir = std::env::temp_dir();
    input_dir.push("websanitizer_batch_input");
    let mut output_dir = std::env::temp_dir();
    output_dir.push("websanitizer_batch_output");

    let sub_dir = input_dir.join("subfolder");
    fs::create_dir_all(&sub_dir).unwrap();
    fs::create_dir_all(&output_dir).unwrap();

    let file1 = input_dir.join("pagina1.html");
    let file_ignored = input_dir.join("documento.exe");
    let file2 = sub_dir.join("pagina2.html");

    fs::write(&file1, "<html><body><script>alert(1)</script><h1>OK</h1></body></html>").unwrap();
    fs::write(&file_ignored, "MALICIOUS_EXE_BINARY_DATA").unwrap();
    fs::write(&file2, "<html><body><h1 onclick=\"bad()\">Sub Page</h1></body></html>").unwrap();

    // Scansione directory
    let scanner = DirectoryScanner::new(vec!["html".to_string()], 5, 100);
    let safe_files = scanner.scan(&input_dir).expect("Scansione fallita");

    assert_eq!(safe_files.len(), 2, "Devono essere trovati solo i 2 file .html");
    assert!(!safe_files.contains(&file_ignored), "Il file .exe doveva essere ignorato");

    // Esecuzione pipeline su tutti i file trovati
    let policy = default_policy();
    let mut detailed_results = Vec::new();

    for file_path in &safe_files {
        let raw_html = fs::read_to_string(file_path).unwrap();
        let mut engine = SanitizerEngine::new();
        engine.add_rule(Box::new(TagAllowListRule { config: policy.html.clone() }));
        engine.add_rule(Box::new(DangerousAttributeRule { url_config: policy.url.clone() }));

        let mut parser = HtmlParser::new(&raw_html);
        let dom = parser.parse().unwrap();
        let (sanitized_dom, actions) = engine.run(dom);

        let sanitized_html: String = sanitized_dom.iter().map(|n| n.to_html_string()).collect();

        detailed_results.push(SanitizationReport {
            input_source: file_path.to_string_lossy().to_string(),
            status: "Cleaned".to_string(),
            actions,
            sanitized_html,
        });
    }

    // Verifica report batch
    let total_threats: usize = detailed_results.iter().map(|r| r.actions.len()).sum();

    let batch_report = BatchReport {
        total_processed: detailed_results.len() as u32,
        total_threats_removed: total_threats as u32,
        success_count: detailed_results.len() as u32,
        error_count: 0,
        detailed_results,
    };

    assert_eq!(batch_report.total_processed, 2);
    assert!(batch_report.total_threats_removed >= 2);

    // Cleanup
    let _ = fs::remove_dir_all(input_dir);
    let _ = fs::remove_dir_all(output_dir);
}


//Inizializza ThreadPool (worker concurrenti), SharedState e canale MPSC.
//e poi invia molteplici Job::File al pool per elaborazione in parallelo.
#[test]
fn test_integration_multithread_batch_processing() {
    // Creiamo 3 file HTML temporanei infetti
    let mut temp_files = Vec::new();
    let temp_dir = std::env::temp_dir();
    let output_dir = temp_dir.join("websanitizer_multithread_output");
    let _ = fs::create_dir_all(&output_dir);

    for i in 1..=3 {
        let file_path = temp_dir.join(format!("multithread_test_{}.html", i));
        let content = format!(
            "<html><body><script>alert('xss_{}')</script><h1>File {}</h1></body></html>",
            i, i
        );
        fs::write(&file_path, content).unwrap();
        temp_files.push(file_path);
    }

    // Mock della configurazione CLI
    let cli = Cli {
        inputs: temp_files.iter().map(|p| p.to_string_lossy().to_string()).collect(),
        output_dir: output_dir.clone(),
        policy_path: None,
        max_bytes: 10_048_576,
        timeout_seconds: 30,
        threads: Some(2), // 2 worker thread
        max_depth: 1,
        max_requests: 50,
        report_file: temp_dir.join("multithread_report.json"),
    };
    let cli_config = Arc::new(cli);

    // Inizializzazione dello Stato Condiviso e del Canale MPSC
    let shared_state = Arc::new(SharedState::new(HashSet::new()));
    let (result_sender, result_receiver) = mpsc::channel();

    // Avvio del ThreadPool con 2 worker thread
    let pool = ThreadPool::new(
        2,
        Arc::clone(&shared_state),
        result_sender,
        Arc::clone(&cli_config),
    );

    // Inoltro dei Job al ThreadPool
    for file_path in &temp_files {
        let path_str = file_path.to_string_lossy().to_string();
        pool.execute(Job::File(path_str));
    }

    // Facciamo il drop del pool per permettere la chiusura pulita dei canali quando finiscono i job
    drop(pool);

    // Raccolta concorrente dei risultati
    let num_jobs = temp_files.len();
    let mut success_count = 0;

    for _ in 0..num_jobs {
        if let Ok(result) = result_receiver.recv() {
            assert!(result.error.is_none(), "L'elaborazione del file ha restituito un errore unexpected");
            assert!(result.report.is_some());

            let report = result.report.unwrap();
            assert!(!report.actions.is_empty(), "I tag script dovevano produrre azioni di sanitizzazione");
            success_count += 1;
        }
    }

    // Verifiche Thread-Safety e Statistiche Atomiche
    assert_eq!(success_count, 3, "Tutti e 3 i job dovevano essere completati");

    let total_processed = shared_state.total_processed.load(Ordering::Relaxed);
    let total_threats = shared_state.threats_removed.load(Ordering::Relaxed);

    assert_eq!(total_processed, 3, "Lo SharedState doveva registrare 3 file elaborati");
    assert!(total_threats >= 3, "Lo SharedState doveva registrare almeno 3 minacce rimosse");

    // Cleanup
    for file_path in temp_files {
        let _ = fs::remove_file(file_path);
    }
    let _ = fs::remove_dir_all(output_dir);
}