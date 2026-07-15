/*• Reporting: for every input, emit a structured report listing each sanitisation action (rule fired,
location in the document, original fragment, replacement) */
use serde::{Serialize, Deserialize}; //serde (per la serializzazione in JSON)

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
}
/*Un singolo input (es. vecchio_sito.htm) può contenere molteplici violazioni (es. un tag script, un iframe malevolo, un link sospetto).
Quindi: SanitizationReport contiene un Vec<SanitizationAction> (una lista di azioni). */

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
        };

        // 2. Proviamo a serializzarlo in JSON
        let json = serde_json::to_string(&report).expect("La serializzazione è fallita");

        // 3. Verifichiamo che il JSON contenga le chiavi corrette
        assert!(json.contains("XSS_SCRIPT_REMOVAL"));
        assert!(json.contains("test.html"));
        println!("JSON prodotto: {}", json);
    }
}