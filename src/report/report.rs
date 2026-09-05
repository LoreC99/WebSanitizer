use serde::{Serialize, Deserialize}; //serde (per la serializzazione in JSON)

#[derive(Deserialize)]
pub struct SanitizationRequest {
    pub url: String,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct SanitizationAction {
    pub rule_fired: String,      // Es: "XSS_SCRIPT_REMOVAL"
    pub location: String,       // Dove è stata rilevata (linea, tag, ecc.)
    pub original_fragment: String,
    pub replacement: String,    // "Removed", "Sanitized" o "Replaced with [SAFE]"
   
}

#[derive(Serialize, Deserialize, Debug)]
pub struct SanitizationReport {
    pub input_source: String,   // File o URL di origine
    pub status: String,         // "Cleaned", "Rejected" (se troppo grande/pericoloso)
    pub actions: Vec<SanitizationAction>, // Lista delle azioni eseguite
    pub sanitized_html: String
}
/*Un singolo input (es. vecchio_sito.htm) può contenere molteplici violazioni (es. un tag script, un iframe malevolo, un link sospetto).
Quindi: SanitizationReport contiene un Vec<SanitizationAction> (una lista di azioni). */

#[derive(Serialize)]
pub struct BatchReport {
    pub total_processed: u32,
    pub total_threats_removed: u32,
    pub success_count: u32,
    pub error_count: u32,
    pub detailed_results: Vec<SanitizationReport>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_report_serialization() {
        // 1. Creiamo un report di esempio
        let action = SanitizationAction {
            rule_fired: "XSS_SCRIPT_REMOVAL".to_string(),
            location: "line 10".to_string(),
            original_fragment: "<script>alert(1)</script>".to_string(),
            replacement: "[REMOVED]".to_string(),
        };

        let report = SanitizationReport {
            input_source: "test.html".to_string(),
            status: "Cleaned".to_string(),
            actions: vec![action],
            sanitized_html: "<div>Contenuto pulito</div>".to_string(), // <--- Campo aggiunto
        };

        // 2. Proviamo a serializzarlo in JSON
        let json = serde_json::to_string(&report).expect("La serializzazione è fallita");

        // 3. Verifichiamo che il JSON contenga le chiavi e i valori corretti
        assert!(json.contains("XSS_SCRIPT_REMOVAL"));
        assert!(json.contains("test.html"));
        assert!(json.contains("<div>Contenuto pulito</div>")); // <--- Verifica della serializzazione

        println!("JSON prodotto: {}", json);
    }
}