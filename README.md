# rjscan

**rjscan** ist ein Nmap-first Scanner für RMI/JMX-Endpunkte. Er verarbeitet Nmap-XML-Ausgaben von `nmap -sV -sC -oX scan.xml`, erkennt Kandidaten (`rmi_registry`, `rmi_endpoint`, `jmx_rmi`), folgt abgeleiteten Endpunkten per BFS-Graph und schreibt strukturierte Ergebnisse inklusive Evidence-Dateien.

## Features
- **Nmap XML Parsing** für Hosts, Ports, Services, Versionen und Script-Ausgaben.
- **Endpoint-Erkennung** für RMI/JMX inklusive stabiler Endpoint-IDs.
- **Derived-Endpoint-Graph**: BFS bis `--max-depth`, Dedupe, Evidence-Referenzen.
- **Enumeration (read-only)** für RMI-Registry und JMX (stubs, nicht destruktiv).
- **Verification-Checks (Plugins)**: `auth_required`, `tls_required`, `error_oracle`, `sink_indicators`, `gadget_detect` mit Evidence + SHA256-Referenzen.
- **Gadget & Chain Detection** über KB-Dateien (`kb/gadgets.yml`, `kb/chains.yml`).
- **PoC-Mode mit Windows-RCE-Proof**: ExploitRunner + Verifier, keine eingebauten Exploit-Chains.
- **Verifier Backends**: `callback_http` (default), `smb_share`, optional `winrm`.
- **Stabile Outputs**: `results.json`, optional `results.ndjson`, `findings.md`, `graph.json`, `meta.json`, `evidence/`.

## Installation
```bash
python -m venv .venv
source .venv/bin/activate
pip install -e .
```

## Quickstart
```bash
rjscan --nmap-xml scan.xml
```

## Modi
- `enum` (Default): Enumeration + Ausgabe der Ergebnisse.
- `verify`: Nicht-destruktive Prüfungen mit Evidence-Ausgaben.
- `assess`: Kombination aus Enum + Verify.
- `poc`: Nur mit `--i-accept-risk`. Führt ausschließlich **user-supplied** ExploitRunner aus.

## PoC-Architektur (Windows RCE Proof)
`rjscan` trennt strikt zwischen ExploitRunner (user-supplied) und Verifier (built-in). Ein Endpoint wird **nur** `EXPLOITABLE_CONFIRMED`, wenn der Verifier einen gültigen Windows-RCE-Proof bestätigt:

- **File-Write Proof (Preferred)**: Datei `C:\Pentest_RMI_<YYYY-MM-DD>.txt` mit Timestamp, `whoami`, `hostname`.
- **Command Output Proof**: `whoami` oder `hostname` Output kommt zurück.

## Beispiele
### Verify-Mode
```bash
rjscan --nmap-xml scan.xml --mode verify --max-depth 2 --ndjson
```

### PoC-Mode (nur mit Risiko-Akzeptanz)
```bash
rjscan --nmap-xml scan.xml --mode poc --i-accept-risk \
  --poc-runner ./poc_runners/http_callback_runner.py \
  --poc-proof filewrite \
  --callback-bind 127.0.0.1 --callback-port 8081
```

### SMB Verifier
```bash
rjscan --nmap-xml scan.xml --mode poc --i-accept-risk \
  --poc-runner ./poc_runners/http_callback_runner.py \
  --verifier smb_share --smb-share-path /mnt/share --smb-share-subdir rjscan
```

## CLI Flags (PoC/Verifier)
- `--poc-runner <file.py>` (repeatable)
- `--poc-proof filewrite|cmd|both` (default: `filewrite`)
- `--poc-file-path "C:\\Pentest_RMI_<DATE>.txt"`
- `--poc-file-template "Timestamp: ..."`
- `--poc-cleanup true|false` (default: false)
- `--verifier auto|callback_http|smb_share|winrm` (default: auto)
- Callback: `--callback-bind <host> --callback-port <port>` oder `--callback-url <url>`
- SMB: `--smb-share-path <path> --smb-share-subdir <subdir>`

## Gadget & Chain Matching
- Gadgets werden über `kb/gadgets.yml` anhand von Indikatoren erkannt.
- Chains werden in `kb/chains.yml` als Kombination aus Gadget-Namen definiert.
- Die Treffer erscheinen in `gadget_detect` Details als `matches` und `chains`.

## ExploitRunner Plugin-Schnittstelle
ExploitRunner müssen `RUNNER_ID`, `TITLE` und eine `async def run(ctx, target, payload_spec)` Funktion bereitstellen.

```python
# poc_runners/custom_runner.py
RUNNER_ID = "custom"
TITLE = "Custom Runner"

async def run(ctx, target, payload_spec):
    # ctx enthält callback_url, callback_token, verifier, run_id
    # target enthält host, port, kind
    # payload_spec enthält proof, file_path, file_template
    return {
        "success": True,
        "execution_channel": {
            "callback_token": "token123",
            "cmd_output": {"whoami": "lab\\user", "hostname": "WINHOST"},
        },
        "evidence_refs": [],
        "notes": [],
    }
```

### Beispiel-Runner (Wrapper)
Der mitgelieferte `poc_runners/http_callback_runner.py` ist ein **Wrapper**, der externe Tools aufruft. Er enthält **keine** Exploit-Chain. Konfiguration:

- `RJSCAN_RUNNER_CMD`: Kommando-Template, z. B. `tool --target {HOST}:{PORT} --callback {CALLBACK_URL}`
- `RJSCAN_RUNNER_RESULT`: Optionaler Pfad zu einer JSON-Datei, die der externe Runner schreibt.

## Outputs
Jeder Lauf erzeugt ein Verzeichnis `rjscan-run-<timestamp>-<id>/`:
- `results.json`: Vollständige Ergebnisse pro Endpoint.
- `results.ndjson`: Optional (Zeile pro Endpoint).
- `findings.md`: Menschlich lesbare Zusammenfassung inkl. PoC Proof.
- `graph.json`: Endpoint-Graph mit Evidence-Referenzen.
- `meta.json`: Lauf-Metadaten.
- `evidence/`: Evidence-Dateien mit SHA256-Referenzen.

## Sicherheit & Datenschutz
- **Keine eingebauten Exploit-Chains**.
- **PoC-Ausführung nur mit `--i-accept-risk`**.
- **Keine Ausgabe von Credentials** (Nutzername/Passwort werden nicht geloggt).
- **Nicht destruktiv** in `enum`/`verify`/`assess`.

## Tests
```bash
pytest
```
