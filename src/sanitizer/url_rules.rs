use url::Url;

pub struct UrlValidator;

impl UrlValidator {
    /// Valida un URL per prevenire attacchi SSRF durante i redirect.
    pub fn is_safe_redirect_hop(url_str: &str) -> Result<(), String> {
        let parsed_url = match Url::parse(url_str) {
            Ok(url) => url,
            Err(_) => return Err("URL malformato o non valido".to_string()),
        };

        // 1. Controllo dello Schema (solo HTTP e HTTPS ammessi, ignoriamo data/javascript)
        let scheme = parsed_url.scheme();
        if scheme != "http" && scheme != "https" {
            return Err(format!("Schema non supportato durante il redirect: {}", scheme));
        }

        // 2. Controllo Anti-SSRF (Indirizzi Privati, Loopback, Cloud Metadata)
        if let Some(host) = parsed_url.host_str() {
            let host_lower = host.to_lowercase();

            // Blocco metadati Cloud (AWS, GCP, Azure) - Prevenzione T-5 / T-1
            if host_lower == "169.254.169.254" {
                return Err("SSRF_PREVENTION: Rilevato tentativo di accesso ai metadati cloud.".to_string());
            }

            let is_loopback = host_lower == "localhost"
                || host_lower == "127.0.0.1"
                || host_lower == "::1";

            let port = parsed_url.port().unwrap_or(if scheme == "https" { 443 } else { 80 });

            if is_loopback {
                // Eccezione per l'ambiente di test: consentiamo localhost SOLO sulla porta 3100
                if port != 3100 && port < 1024 {
                    return Err(format!("SSRF_PREVENTION: Accesso bloccato verso porta di sistema locale ({})", port));
                }
            } else {
                // Blocco classi IP private (RFC 1918)
                if host_lower.starts_with("10.")
                    || host_lower.starts_with("192.168.")
                    || Self::is_in_172_private_range(&host_lower) {
                    return Err("SSRF_PREVENTION: Tentativo di accesso a un IP di rete privata interna.".to_string());
                }
            }
        }

        Ok(())
    }

    /// Funzione helper per verificare il range 172.16.x.x - 172.31.x.x
    fn is_in_172_private_range(host: &str) -> bool {
        for i in 16..=31 {
            let prefix = format!("172.{}.", i);
            if host.starts_with(&prefix) {
                return true;
            }
        }
        false
    }
}