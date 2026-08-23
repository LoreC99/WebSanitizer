# WebSanitizer

## Caratteristiche Principali

- **Architettura Modulare (CLI + Crate Library)**: Il motore di bonifica risiede in una libreria riutilizzabile (`lib.rs`), fruibile sia tramite CLI che integrabile in pipeline esterne.
- **Policy Dichiarative (TOML)**: Configurazione flessibile delle regole di sicurezza tramite file `.toml` (`policies/strict.toml`).
- **Difesa da Vettori di Attacco**:
  - **XSS (Cross-Site Scripting)**: Rimozione di tag `<script>`, handler inline (`onclick`, `onerror`), pseudo-protocolli `javascript:` e `data:` URIs.
  - **MIME Confusion & Content Sniffing**: Ispezione dei Magic Bytes dei file (PNG, PDF, GZIP, XML) senza fidarsi delle estensioni o degli header dichiarati.
  - **DoS & Resource Exhaustion**: Protezione da Decompression Bombs, XML Entity Expansion (Billion Laughs), attacchi di annidamento profondo HTML e limiti rigidi sulla dimensione delle risorse.
  - **Active Document Content**: Rilevamento di script attivi e `OpenAction` all'interno di documenti PDF.
  - **SSRF & Link Inspection**: Blocco automatizzato di IP privati (RFC1918), IP di loopback e metadata Cloud (IMDS `169.254.169.254`). Rilevamento di attacchi IDN Homograph e Punycode Spoofing.
- **Concorrenza & Multi-Threading**: Worker thread pool basato su **Tokio** e sincronizzazione tramite `Arc` e `Mutex`.
- **Memory Safety & Zero-Copy**: Implementazione 100% Safe Rust con la semantica Copy-on-Write (`std::borrow::Cow`) e slice `&str`.

---

## Struttura del Repository

```text
WebSanitizer/
├── src/                    # Codice sorgente Rust (CLI + Library)
│   ├── cli/                # Parsing argomenti CLI (Clap)
│   ├── config/             # Caricamento policy TOML
│   ├── input/              # Astrazione su file locali, directory e URL remoti
│   ├── parser/             # Parser HTML/DOM sicuro
│   ├── sanitizer/          # Motore a regole di bonifica (HTML, CSS, risorse)
│   ├── scheduler/          # Worker thread pool per elaborazione batch
│   ├── report/             # Generazione report in JSON
│   └── utils/              # Funzioni helper di bonifica
├── tests/                  # 49 Test d'integrazione e verifica del corpus
├── benches/                # Benchmark 100% Rust (cargo bench)
├── corpus_test/            # Test corpus (campioni benigni e malevoli)
├── policies/               # File di policy dichiarative (strict.toml)
└── scripts/plots/          # Grafici PNG generati dall'evaluation (plots)
```

---

## Compilazione

## Esempi di Utilizzo (CLI)

### 1. Bonifica di un singolo file HTML
```powershell
cargo run --release -- -i corpus_test/benign/normale.html -o ./sanitized_output
```

### 2. Scansione batch concorrente di un'intera directory
```powershell
cargo run --release -- -i corpus_test/ -o ./sanitized_output -t 4
```

### 3. Utilizzo di una policy personalizzata
```powershell
cargo run --release -- -i corpus_test/ -o ./sanitized_output -p policies/strict.toml
```

---

## Esecuzione dei Test e Valutazione 

### 1. Esecuzione della Suite Completa di Test (49 Test)
```powershell
cargo test
```

### 2. Valutazione della Correttezza (Detection Rate & Falsi Positivi)
Per eseguire la scansione del corpus locale e visualizzare la tabella sintetica con percentuali:
```powershell
cargo test local_eval -- --nocapture
```

### 3. Benchmark di Prestazioni, Scalabilità e Grafici (Plots)
Per eseguire la suite di benchmark nativa in Rust che misura **Throughput, Latenza, Speed-Up Multi-Thread, Memoria RAM** e rigenera i grafici PNG in `scripts/plots/`:
```powershell
cargo bench
```

---



