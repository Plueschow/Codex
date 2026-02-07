from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import time
from concurrent.futures import ThreadPoolExecutor
from typing import Any, Dict, List, Optional, Tuple
import uuid

from rjscan.callback import CallbackServer
from rjscan.evidence import write_evidence_json, write_evidence_text
from rjscan.enumerate import enumerate_jmx, enumerate_rmi_registry
from rjscan.graph import Endpoint, bfs_graph, extract_hints
from rjscan.kb import load_gadgets
from rjscan.nmap_parser import parse_nmap_xml, PortInfo
from rjscan.poc import load_poc_plugin
from rjscan.verify import run_checks


def detect_candidates(host: str, port: PortInfo) -> Optional[Endpoint]:
    service_text = " ".join([port.service, port.product, port.version, port.extrainfo]).lower()
    if "jmx" in service_text:
        kind = "jmx_rmi"
    elif "rmi registry" in service_text or "rmiregistry" in service_text:
        kind = "rmi_registry"
    elif "rmi" in service_text or "java-rmi" in service_text:
        kind = "rmi_endpoint"
    else:
        return None
    return Endpoint(host=host, port=port.port, kind=kind)


def build_hint_provider(
    endpoints: List[Endpoint],
    host_ports: Dict[Tuple[str, int], PortInfo],
    evidence_dir: Path,
) -> Dict[str, List[Tuple[str, int, List[Dict[str, str]]]]]:
    hint_provider: Dict[str, List[Tuple[str, int, List[Dict[str, str]]]]] = {}
    for endpoint in endpoints:
        port_info = host_ports.get((endpoint.host, endpoint.port))
        if not port_info:
            continue
        for script in port_info.scripts:
            hints = extract_hints(script.output)
            if not hints:
                continue
            evidence = [
                write_evidence_text(
                    evidence_dir,
                    f"hint-{endpoint.endpoint_id}-{script.script_id}.txt",
                    script.output,
                )
            ]
            for host, port in hints:
                hint_provider.setdefault(endpoint.endpoint_id, []).append((host, port, evidence))
    return hint_provider


def rate_limit(sleep_s: float) -> None:
    if sleep_s > 0:
        time.sleep(sleep_s)


def run_enum(
    endpoint: Endpoint,
    timeout: float,
    jmx_user: Optional[str],
    jmx_pass: Optional[str],
    rate_limit_s: float,
) -> Dict[str, Any]:
    rate_limit(rate_limit_s)
    if endpoint.kind == "rmi_registry":
        result = enumerate_rmi_registry(endpoint.host, endpoint.port, timeout)
    elif endpoint.kind == "jmx_rmi":
        result = enumerate_jmx(endpoint.host, endpoint.port, timeout, jmx_user, jmx_pass)
    else:
        result = enumerate_rmi_registry(endpoint.host, endpoint.port, timeout)
    return {
        "registry_names": result.registry_names,
        "jmx_domains": result.jmx_domains,
        "jmx_mbeans": result.jmx_mbeans,
        "notes": result.notes,
    }


def build_findings_markdown(results: List[Dict[str, Any]]) -> str:
    lines = ["# rjscan findings", ""]
    for item in results:
        lines.append(f"## {item['endpoint_id']}")
        lines.append(f"- Host: {item['host']}")
        lines.append(f"- Port: {item['port']}")
        lines.append(f"- Kind: {item['kind']}")
        lines.append(f"- Exploitability: {item['exploitability']}")
        lines.append("")
    return "\n".join(lines)


def compute_exploitability(findings: List[Dict[str, Any]]) -> str:
    poc = next((finding for finding in findings if finding["name"] == "poc" and finding["status"] == "observed"), None)
    if poc:
        return "EXPLOITABLE_CONFIRMED"
    sink = next(
        (finding for finding in findings if finding["name"] == "sink_indicators" and finding["status"] == "observed"),
        None,
    )
    gadget = next(
        (finding for finding in findings if finding["name"] == "gadget_detect" and finding["status"] == "observed"),
        None,
    )
    if sink and gadget:
        details = gadget.get("details") or {}
        matches = details.get("matches", [])
        if any(match.endswith(":HIGH") for match in matches):
            return "LIKELY"
    if any(finding["status"] == "observed" for finding in findings):
        return "INCONCLUSIVE"
    return "NOT_OBSERVED"


def main() -> None:
    parser = argparse.ArgumentParser(description="rjscan - Nmap-first RMI/JMX scanner")
    parser.add_argument("--nmap-xml", required=True, help="Path to Nmap XML (-oX)")
    parser.add_argument("--mode", choices=["enum", "verify", "assess", "poc"], default="enum")
    parser.add_argument("--max-depth", type=int, default=1)
    parser.add_argument("--ndjson", action="store_true", help="Write results.ndjson")
    parser.add_argument("--timeout", type=float, default=3.0)
    parser.add_argument("--concurrency", type=int, default=4)
    parser.add_argument("--rate-limit", type=float, default=0.0)
    parser.add_argument("--jmx-user", default=None)
    parser.add_argument("--jmx-pass", default=None)
    parser.add_argument("--i-accept-risk", action="store_true")
    parser.add_argument("--poc-plugin", action="append", default=[])
    parser.add_argument("--callback-listen", default=None, help="host:port to bind callback listener")
    parser.add_argument("--callback-url", default=None, help="External callback base URL")
    args = parser.parse_args()

    if args.mode == "poc" and not args.i_accept_risk:
        raise SystemExit("poc mode requires --i-accept-risk")

    run_id = time.strftime("%Y%m%d-%H%M%S")
    run_dir = Path(os.getcwd()) / f"rjscan-run-{run_id}-{uuid.uuid4().hex[:8]}"
    run_dir.mkdir(parents=True, exist_ok=True)
    evidence_dir = run_dir / "evidence"

    hosts = parse_nmap_xml(args.nmap_xml)
    endpoints: List[Endpoint] = []
    host_ports: Dict[Tuple[str, int], PortInfo] = {}

    for host in hosts:
        for port in host.ports:
            host_ports[(host.address, port.port)] = port
            endpoint = detect_candidates(host.address, port)
            if endpoint:
                endpoints.append(endpoint)

    hint_provider = build_hint_provider(endpoints, host_ports, evidence_dir)
    endpoints, edges = bfs_graph(endpoints, hint_provider, args.max_depth)

    gadgets = load_gadgets(Path(__file__).resolve().parent.parent / "kb" / "gadgets.yml")

    callback_server: Optional[CallbackServer] = None
    callback_base: Optional[str] = None

    if args.callback_listen:
        host, port = args.callback_listen.split(":")
        callback_server = CallbackServer(host, int(port))
        callback_server.start()
        callback_base = callback_server.address
    elif args.callback_url:
        callback_base = args.callback_url.rstrip("/")

    results: List[Dict[str, Any]] = []

    def process_endpoint(endpoint: Endpoint) -> Dict[str, Any]:
        enum_data = {}
        findings: List[Dict[str, Any]] = []
        text_sources: List[str] = []
        port_info = host_ports.get((endpoint.host, endpoint.port))
        if port_info:
            for script in port_info.scripts:
                text_sources.append(script.output)
        if args.mode in {"enum", "assess", "verify", "poc"}:
            enum_data = run_enum(endpoint, args.timeout, args.jmx_user, args.jmx_pass, args.rate_limit)
            text_sources.extend(enum_data.get("notes", []))
        combined_text = "\n".join(text_sources)
        if args.mode in {"verify", "assess", "poc"}:
            check_dir = evidence_dir / endpoint.endpoint_id
            for finding in run_checks(combined_text, check_dir, gadgets):
                findings.append({
                    "name": finding.name,
                    "status": finding.status,
                    "evidence": finding.evidence,
                    "details": finding.details,
                })
        if args.mode == "poc":
            for plugin_path in args.poc_plugin:
                plugin = load_poc_plugin(Path(plugin_path))
                token = uuid.uuid4().hex
                callback_url = None
                if callback_base:
                    callback_url = f"{callback_base}/?token={token}"
                context = {
                    "endpoint": {
                        "host": endpoint.host,
                        "port": endpoint.port,
                        "kind": endpoint.kind,
                    },
                    "callback_url": callback_url,
                }
                plugin(context)
                if callback_server and callback_url:
                    check_dir = evidence_dir / endpoint.endpoint_id
                    if callback_server.registry.get(token):
                        ref = write_evidence_json(
                            check_dir,
                            f"poc-callback-{token}.json",
                            {"token": token, "path": callback_url},
                        )
                        findings.append({
                            "name": "poc",
                            "status": "observed",
                            "evidence": [ref],
                            "details": None,
                        })
            if args.poc_plugin and not any(f["name"] == "poc" for f in findings):
                findings.append({"name": "poc", "status": "not_observed", "evidence": [], "details": None})
        exploitability = compute_exploitability(findings) if findings else "INCONCLUSIVE"
        return {
            "endpoint_id": endpoint.endpoint_id,
            "host": endpoint.host,
            "port": endpoint.port,
            "kind": endpoint.kind,
            "enum": enum_data,
            "findings": findings,
            "exploitability": exploitability,
        }

    with ThreadPoolExecutor(max_workers=args.concurrency) as executor:
        for result in executor.map(process_endpoint, endpoints):
            results.append(result)

    results = sorted(results, key=lambda item: (item["host"], item["port"], item["kind"]))

    (run_dir / "results.json").write_text(json.dumps(results, indent=2, sort_keys=True))
    if args.ndjson:
        (run_dir / "results.ndjson").write_text("\n".join(json.dumps(item) for item in results))

    graph_payload = {
        "nodes": [
            {"id": endpoint.endpoint_id, "host": endpoint.host, "port": endpoint.port, "kind": endpoint.kind}
            for endpoint in endpoints
        ],
        "edges": [
            {"source": edge.source_id, "target": edge.target_id, "evidence": edge.evidence}
            for edge in edges
        ],
    }
    (run_dir / "graph.json").write_text(json.dumps(graph_payload, indent=2, sort_keys=True))

    (run_dir / "findings.md").write_text(build_findings_markdown(results))

    meta = {
        "run_id": run_id,
        "mode": args.mode,
        "targets": len(results),
        "max_depth": args.max_depth,
        "ndjson": args.ndjson,
    }
    (run_dir / "meta.json").write_text(json.dumps(meta, indent=2, sort_keys=True))

    if callback_server:
        callback_server.stop()


if __name__ == "__main__":
    main()
