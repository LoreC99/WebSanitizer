use std::fs;
use std::path::{Path, PathBuf};
use crate::cli::cli::Cli;
use crate::config::Policy;
use crate::parser::html::HtmlParser;
use crate::report::{BatchReport, SanitizationAction, SanitizationReport};
use crate::sanitizer::engine::SanitizerEngine;
use crate::sanitizer::html_rules::{DangerousAttributeRule, IdnHomographRule, MetaRefreshRule, SsrfAttributeRule, TagAllowListRule};
use crate::sanitizer::resource_rules::{CssSanitizer, DetectedType, ImageCheckResult, ImageSanitizer, PdfCheckResult, PdfSanitizer};
use crate::scheduler::workers::JobResult;

/// Stampa a video la configurazione CLI attiva, omettendo i parametri di default non modificati.
pub fn print_active_config(cli: &Cli) {
    println!("⚙️  Configurazione Parametri Attiva:");
    println!("   - Target in input  : {:?}", cli.inputs);

    // --- Parametri Opzionali ---
    if let Some(ref policy) = cli.policy_path {
        println!("   - Policy custom    : {:?}", policy);
    }
    if let Some(t) = cli.threads {
        println!("   - Threads Worker   : {}", t);
    }

    // --- Parametri con Default ---
    if cli.output_dir.to_str() != Some("./sanitized_output") {
        println!("   - Output Dir       : {:?}", cli.output_dir);
    }
    if cli.max_bytes != 10485760 {
        println!("   - Max Bytes (DoS)  : {} bytes", cli.max_bytes);
    }
    if cli.timeout_seconds != 30 {
        println!("   - Timeout Rete     : {} secondi", cli.timeout_seconds);
    }
    if cli.max_depth != 0 {
        println!("   - Max Depth (Net)  : {}", cli.max_depth);
    }
    if cli.max_requests != 50 {
        println!("   - Max Reqs (Net)   : {}", cli.max_requests);
    }
    if cli.dir_max_depth != 10 {
        println!("   - Max Depth (Dir)  : {}", cli.dir_max_depth);
    }
    if cli.dir_max_files != 10000 {
        println!("   - Max Files (Dir)  : {}", cli.dir_max_files);
    }
    if cli.report_file.to_str() != Some("./sanitizer_report.json") {
        println!("   - File di Report   : {:?}", cli.report_file);
    }
    println!("==================================================\n");
}

/// Salva il contenuto HTML pulito generando un nome file sicuro.
pub fn save_sanitized_html(output_dir: &Path, target: &str, html_content: &str) {
    let safe_filename = target.replace(&['/', ':', '\\', '?', '&', '=', '#'][..], "_");
    let file_path = output_dir.join(format!("{}.html", safe_filename));

    if let Err(e) = fs::write(&file_path, html_content) {
        eprintln!("   ⚠️ Errore nel salvare il file HTML per {}: {}", target, e);
    } else {
        println!("   -> Contenuto pulito salvato in: {:?}", file_path);
    }
}

/// Serializza e salva il report globale in formato JSON.
pub fn save_batch_report(report_file: &PathBuf, report: &BatchReport) {
    match serde_json::to_string_pretty(report) {
        Ok(json_string) => {
            if let Err(e) = fs::write(report_file, json_string) {
                eprintln!("❌ Errore durante il salvataggio del report su disco: {}", e);
            } else {
                println!("📄 Report JSON globale salvato con successo in: {:?}", report_file);
            }
        },
        Err(e) => eprintln!("❌ Errore durante la serializzazione del report JSON: {}", e),
    }
}

// ==========================================
// FUNZIONI HELPER PER SNELLIRE IL WORKER
// ==========================================

/// Gestisce tutti i file non testuali o pericolosi individuati dal MimeSniffer.
/// Restituisce `Some(JobResult)` se ha gestito il file, oppure `None` se deve proseguire con HTML/CSS.
pub fn evaluate_mime_type(detected_type: &DetectedType, raw_bytes: &[u8], target_name: &str) -> Option<JobResult> {
    match detected_type {
        DetectedType::Html | DetectedType::Unknown => None, // Passa il controllo all'elaborazione testuale
        DetectedType::Png => {
            Some(match ImageSanitizer::check_dimensions(raw_bytes) {
                ImageCheckResult::DimensionBomb { width, height } => JobResult {
                    target: target_name.to_string(),
                    report: None,
                    error: Some(format!("REJECTED: Image Dimension Bomb ({}x{} px)", width, height)),
                },
                _ => JobResult {
                    target: target_name.to_string(),
                    report: Some(SanitizationReport {
                        input_source: target_name.to_string(),
                        status: "Clean".to_string(),
                        actions: vec![],
                        sanitized_html: "PNG Image (Validated)".to_string(),
                    }),
                    error: None
                }
            })
        },
        DetectedType::Pdf => {
            Some(match PdfSanitizer::check_active_content(raw_bytes) {
                PdfCheckResult::ActiveContentDetected { details } => JobResult {
                    target: target_name.to_string(),
                    report: None,
                    error: Some(format!("REJECTED: PDF Active Content ({})", details)),
                },
                _ => JobResult {
                    target: target_name.to_string(),
                    report: Some(SanitizationReport {
                        input_source: target_name.to_string(),
                        status: "Clean".to_string(),
                        actions: vec![],
                        sanitized_html: "PDF Document (Validated)".to_string(),
                    }),
                    error: None
                }
            })
        },
        DetectedType::Gzip => Some(JobResult {
            target: target_name.to_string(),
            report: None,
            error: Some("REJECTED: Decompression Bomb / Gzip payload detected".to_string()),
        }),
        DetectedType::Xml => Some(JobResult {
            target: target_name.to_string(),
            report: None,
            error: Some("REJECTED: XML content detected (potential XXE)".to_string()),
        }),
    }
}

/// Elabora la logica di sanitizzazione per i fogli di stile CSS
pub fn process_css(raw_content: &str, target_name: &str) -> JobResult {
    let sanitized_css = CssSanitizer::sanitize(raw_content);
    let mut report_actions = Vec::new();

    if sanitized_css != raw_content {
        report_actions.push(SanitizationAction {
            rule_fired: "MALICIOUS_CSS_SANITIZED".to_string(),
            location: "Stylesheet".to_string(),
            original_fragment: "Active CSS Vectors".to_string(),
            replacement: "Stripped".to_string(),
        });
    }

    let status = if report_actions.is_empty() { "Clean".to_string() } else { "Cleaned".to_string() };

    JobResult {
        target: target_name.to_string(),
        report: Some(SanitizationReport {
            input_source: target_name.to_string(),
            status,
            actions: report_actions,
            sanitized_html: sanitized_css,
        }),
        error: None
    }
}

/// Elabora l'intera pipeline di parsing e sanitizzazione HTML
pub fn process_html(raw_content: &str, target_name: &str, policy: &Policy) -> JobResult {
    let clean_raw_html = raw_content
        .replace("<!doctype html>", "")
        .replace("<!DOCTYPE html>", "")
        .replace("<!DOCTYPE HTML>", "");

    let mut parser = HtmlParser::new(&clean_raw_html);
    match parser.parse() {
        Ok(dom) => {
            let mut engine = SanitizerEngine::new();
            let mut active_html_policy = policy.html.clone();

            if active_html_policy.remove_iframes {
                active_html_policy.allowed_tags.retain(|tag| !["iframe", "object", "embed"].contains(&tag.as_str()));
            }
            if !active_html_policy.allow_scripts {
                active_html_policy.allowed_tags.retain(|tag| tag != "script");
            }

            engine.add_rule(Box::new(TagAllowListRule { config: active_html_policy.clone() }));
            if active_html_policy.block_meta_refresh {
                engine.add_rule(Box::new(MetaRefreshRule { config: active_html_policy }));
            }
            engine.add_rule(Box::new(DangerousAttributeRule { url_config: policy.url.clone() }));
            engine.add_rule(Box::new(SsrfAttributeRule { config: policy.url.clone() }));
            engine.add_rule(Box::new(IdnHomographRule));

            let (clean_dom, report_actions) = engine.run(dom);
            let mut clean_html_string = String::new();
            for node in clean_dom {
                clean_html_string.push_str(&node.to_html_string());
            }

            let status = if report_actions.is_empty() { "Clean".to_string() } else { "Cleaned".to_string() };

            JobResult {
                target: target_name.to_string(),
                report: Some(SanitizationReport {
                    input_source: target_name.to_string(),
                    status,
                    actions: report_actions,
                    sanitized_html: clean_html_string,
                }),
                error: None
            }
        },
        Err(e) => JobResult {
            target: target_name.to_string(),
            report: None,
            error: Some(format!("Errore HTML Parser: {:?}", e)),
        }
    }
}