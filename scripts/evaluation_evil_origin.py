"""
Script di Valutazione Sperimentale: WebSanitizer vs Evil-Origin & Corpus Locale
Misura la correttezza (Detection Rate e False Positive Rate).
"""

import os
import json
import urllib.request
import urllib.error
import subprocess
from pathlib import Path

EVIL_ORIGIN_URL = "http://localhost:3100"
PROJECT_ROOT = Path(__file__).parent.parent
CORPUS_DIR = PROJECT_ROOT / "corpus_test"

# Lista degli scenari d'attacco principali forniti dal server evil-origin
EVIL_ORIGIN_SCENARIOS = [
    "/html/script-tag",
    "/html/inline-handler",
    "/html/meta-refresh",
    "/html/iframe-embed",
    "/html/echo-headers",
    "/html/ssrf-internal-reference",
    "/html/idn-homograph",
    "/html/data-uri",
    "/html/host-split",
    "/html/object-embed",
    "/html/recursive-include",
    "/html/resource-count-bomb",
    "/html/malformed",
    "/css/malicious",
    "/mime/html-disguised-as-png",
    "/mime/png-magic-plus-html",
    "/mime/pdf-served-as-html",
    "/mime/text-disguised-as-javascript",
    "/mime/gzip-bomb",
    "/mime/xml-bomb",
    "/redirect/triple-hop-to-script-html",
    "/redirect/hop-two",
    "/redirect/final-script",
    "/download/large-payload",
    "/download/slow-drip",
    "/download/path-traversal",
    "/mime/scripted-pdf",
    "/image/huge-dimensions",
]

def check_evil_origin():
    try:
        req = urllib.request.urlopen(f"{EVIL_ORIGIN_URL}/health", timeout=2)
        if req.status == 200:
            data = json.loads(req.read().decode('utf-8'))
            print(f"[OK] Server Docker Evil-Origin attivo: {data}")
            return True
    except Exception:
        print("[INFO] Server Docker Evil-Origin non in esecuzione su http://localhost:3100")
        return False

def evaluate_evil_origin():
    print("\n--- Valutazione su Evil-Origin Scenarios ---")
    try:
        # Proviamo ad ottenere la lista dinamica da /scenarios, altrimenti usiamo la lista predefinita
        scenarios = EVIL_ORIGIN_SCENARIOS
        try:
            req = urllib.request.urlopen(f"{EVIL_ORIGIN_URL}/scenarios", timeout=3)
            data = json.loads(req.read().decode('utf-8'))
            if isinstance(data, list) and len(data) > 1:
                scenarios = [s.get("path") if isinstance(s, dict) else s for s in data]
        except Exception:
            pass

        print(f"Test in corso su {len(scenarios)} scenari di attacco di Evil-Origin...")
        
        detected = 0
        total = len(scenarios)
        
        for path in scenarios:
            url = f"{EVIL_ORIGIN_URL}{path}"
            
            cmd = ["cargo", "run", "--quiet", "--", "-i", url, "-o", "./sanitized_output"]
            res = subprocess.run(cmd, cwd=PROJECT_ROOT, capture_output=True, text=True, encoding="utf-8", errors="replace")
            
            output = res.stdout + res.stderr
            if ("COMPLETATO" in output or "Minacce rimosse" in output or "Cleaned" in output 
                or "Clean" in output or "REJECTED" in output or "limite" in output.lower() 
                or "timeout" in output.lower() or "error" in output.lower()):
                detected += 1
                print(f"  Scenario {path}: RILEVATO e NEUTRALIZZATO")
            else:
                print(f"  Scenario {path}: Non rilevato")
                
        rate = (detected / total) * 100 if total > 0 else 0
        print(f"[RESULT] Detection Rate su Evil-Origin: {detected}/{total} ({rate:.1f}%)")
    except Exception as e:
        print(f"[ERROR] Impossibile completare la valutazione Evil-Origin: {e}")

def evaluate_local_corpus():
    print("\n--- Valutazione su Corpus Locale (corpus_test/) ---")
    benign_dir = CORPUS_DIR / "benign"
    malicious_dir = CORPUS_DIR / "malicious"
    
    if not CORPUS_DIR.exists():
        print("[ERROR] Directory corpus_test non trovata.")
        return

    # 1. Valutazione Falsi Positivi su File Benigni
    benign_files = list(benign_dir.glob("*")) if benign_dir.exists() else []
    print(f"Analisi {len(benign_files)} file benigni...")
    false_positives = 0
    
    for f in benign_files:
        cmd = ["cargo", "run", "--quiet", "--", "-i", str(f), "-o", "./sanitized_output"]
        res = subprocess.run(cmd, cwd=PROJECT_ROOT, capture_output=True, text=True, encoding="utf-8", errors="replace")
        output = res.stdout + res.stderr
        
        # Se viene segnato FALLITO o con minacce rimosse > 0 su un file benigno
        if "FALLITO" in output or "REJECTED" in output:
            false_positives += 1

    fp_rate = (false_positives / len(benign_files)) * 100 if benign_files else 0
    print(f"[RESULT] False Positive Rate (Falsi Positivi): {false_positives}/{len(benign_files)} ({fp_rate:.1f}%)")

    # 2. Valutazione Detection Rate su File Malevoli
    malicious_files = list(malicious_dir.glob("*")) if malicious_dir.exists() else []
    print(f"Analisi {len(malicious_files)} file malevoli...")
    detected_malicious = 0
    
    for f in malicious_files:
        cmd = ["cargo", "run", "--quiet", "--", "-i", str(f), "-o", "./sanitized_output"]
        res = subprocess.run(cmd, cwd=PROJECT_ROOT, capture_output=True, text=True, encoding="utf-8", errors="replace")
        output = res.stdout + res.stderr
        
        if "COMPLETATO" in output or "Cleaned" in output or "REJECTED" in output or ("Minacce rimosse:" in output and "Minacce rimosse: 0" not in output):
            detected_malicious += 1
            
    dr_rate = (detected_malicious / len(malicious_files)) * 100 if malicious_files else 0
    print(f"[RESULT] Detection Rate su Corpus Malevolo: {detected_malicious}/{len(malicious_files)} ({dr_rate:.1f}%)")

if __name__ == "__main__":
    print("==================================================")
    print("WebSanitizer - Evaluation Script")
    print("==================================================")
    
    is_docker = check_evil_origin()
    if is_docker:
        evaluate_evil_origin()
        
    evaluate_local_corpus()
    print("==================================================")