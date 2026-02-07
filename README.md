# rjscan

**rjscan** ist ein Nmap-first Scanner für RMI/JMX-Endpunkte. Er verarbeitet Nmap-XML-Ausgaben von `nmap -sV -sC -oX scan.xml`, erkennt Kandidaten (`rmi_registry`, `rmi_endpoint`, `jmx_rmi`), folgt abgeleiteten Endpunkten per BFS-Graph und schreibt strukturierte Ergebnisse inklusive Evidence-Dateien.

## Features
- **Nmap XML Parsing** für Hosts, Ports, Services, Versionen und Script-Ausgaben.
- **Endpoint-Erkennung** für RMI/JMX inklusive stabiler Endpoint-IDs.
- **Derived-Endpoint-Graph**: BFS bis `--max-depth`, Dedupe, Evidence-Referenzen.
- **Enumeration (read-only)** für RMI-Registry und JMX (stubs, nicht destruktiv).
- **Verification-Checks (Plugins)**: `auth_required`, `tls_required`, `error_oracle`, `sink_indicators`, `gadget_detect` mit Evidence + SHA256-Referenzen.
- **PoC-Mode nur mit Risiko-Akzeptanz** (`--i-accept-risk`) und **nur user-supplied PoC-Plugins**.
- **Callback-Canary**: lokaler HTTP-Listener oder externer Callback-URL, Evidence-Korrelation.
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
- `poc`: Nur mit `--i-accept-risk`. Führt ausschließlich **user-supplied** PoC-Plugins aus.

## Beispiele
### Verify-Mode
```bash
rjscan --nmap-xml scan.xml --mode verify --max-depth 2 --ndjson
```

### PoC-Mode (nur mit Risiko-Akzeptanz)
```bash
rjscan --nmap-xml scan.xml --mode poc --i-accept-risk \
  --poc-plugin ./poc_example.py --callback-listen 127.0.0.1:8081
```

### Externer Callback
```bash
rjscan --nmap-xml scan.xml --mode poc --i-accept-risk \
  --poc-plugin ./poc_example.py --callback-url https://example.net/callback
```

## Outputs
Jeder Lauf erzeugt ein Verzeichnis `rjscan-run-<timestamp>-<id>/`:
- `results.json`: Vollständige Ergebnisse pro Endpoint.
- `results.ndjson`: Optional (Zeile pro Endpoint).
- `findings.md`: Menschlich lesbare Zusammenfassung.
- `graph.json`: Endpoint-Graph mit Evidence-Referenzen.
- `meta.json`: Lauf-Metadaten.
- `evidence/`: Evidence-Dateien mit SHA256-Referenzen.

## Sicherheit & Datenschutz
- **Keine eingebauten Exploit-Chains**.
- **PoC-Ausführung nur mit `--i-accept-risk`**.
- **Keine Ausgabe von Credentials** (Nutzername/Passwort werden nicht geloggt).
- **Nicht destruktiv** in `enum`/`verify`/`assess`.

## PoC-Plugin-Schnittstelle
PoC-Plugins müssen eine Funktion `run(context)` bereitstellen und dürfen nur **benigne** Callbacks erzeugen.

```python
# poc_example.py

def run(context):
    endpoint = context["endpoint"]
    callback_url = context.get("callback_url")
    # ... user-defined PoC logic ...
    return {"status": "ok", "endpoint": endpoint, "callback": callback_url}
```

## Tests
```bash
pytest
```
