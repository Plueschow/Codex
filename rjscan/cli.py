from __future__ import annotations

import argparse
import asyncio
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
from rjscan.kb import load_chains, load_gadgets
from rjscan.nmap_parser import parse_nmap_xml, PortInfo
from rjscan.poc.verifier_windows import VerifierContext, verify_cmd, verify_file_write
from rjscan.poc_runner import coerce_runner_result, load_runner
from rjscan.verify import run_checks


DEFAULT_POC_FILE_PATH = r"C:\Pentest_RMI_<DATE>.txt"
DEFAULT_POC_FILE_TEMPLATE = "Timestamp: {TIMESTAMP}\nwhoami: {WHOAMI}\nhostname: {HOSTNAME}\n"


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
        if item.get("poc", {}).get("proofs"):
            lines.append("")
            lines.append("### PoC Proof")
            for proof in item["poc"]["proofs"]:
                lines.append(f"- Proof Type: {proof['type']}")
                lines.append(f"- Proof Path: {proof.get('path', 'n/a')}")
                summary = proof.get("summary") or ""
                if summary:
                    lines.append(f"- Proof Summary: {summary}")
                if proof.get("evidence"):
                    lines.append("- Evidence:")
                    for ref in proof["evidence"]:
                        lines.append(f"  - {ref['path']} ({ref['sha256']})")
        lines.append("")
    return "\n".join(lines)


def compute_exploitability(findings: List[Dict[str, Any]], proofs: List[Dict[str, Any]]) -> str:
    if any(proof.get("verified") for proof in proofs):
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
            return "LIKELY_EXPLOITABLE"
    if any(finding["status"] == "observed" for finding in findings):
        return "INCONCLUSIVE"
    return "NOT_OBSERVED"


def parse_bool(value: str) -> bool:
    return value.lower() in {"1", "true", "yes", "y"}


def render_file_path(template: str) -> str:
    date = time.strftime("%Y-%m-%d")
    return template.replace("<DATE>", date).replace("<YYYY-MM-DD>", date)


def run_runner(plugin, ctx: Dict[str, Any], target: Dict[str, Any], payload_spec: Dict[str, Any]) -> Dict[str, Any]:
    loop = asyncio.new_event_loop()
    try:
        result = loop.run_until_complete(plugin.run(ctx, target, payload_spec))
    finally:
        loop.close()
    return result


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
    parser.add_argument("--poc-runner", action="append", default=[])
    parser.add_argument("--poc-proof", choices=["filewrite", "cmd", "both"], default="filewrite")
    parser.add_argument("--poc-file-path", default=DEFAULT_POC_FILE_PATH)
    parser.add_argument("--poc-file-template", default=DEFAULT_POC_FILE_TEMPLATE)
    parser.add_argument("--poc-cleanup", type=str, default="false")
    parser.add_argument("--verifier", choices=["auto", "callback_http", "smb_share", "winrm"], default="auto")
    parser.add_argument("--callback-bind", default=None)
    parser.add_argument("--callback-port", type=int, default=None)
    parser.add_argument("--callback-url", default=None)
    parser.add_argument("--smb-share-path", default=None)
    parser.add_argument("--smb-share-subdir", default=None)
    parser.add_argument("--callback-timeout", type=float, default=5.0)
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
    chains = load_chains(Path(__file__).resolve().parent.parent / "kb" / "chains.yml")

    callback_server: Optional[CallbackServer] = None
    callback_base: Optional[str] = None

    if args.callback_url:
        callback_base = args.callback_url.rstrip("/")
    elif args.callback_bind and args.callback_port:
        callback_server = CallbackServer(args.callback_bind, args.callback_port)
        callback_server.start()
        callback_base = callback_server.address

    smb_share_path = Path(args.smb_share_path) if args.smb_share_path else None

    results: List[Dict[str, Any]] = []

    def process_endpoint(endpoint: Endpoint) -> Dict[str, Any]:
        enum_data = {}
        findings: List[Dict[str, Any]] = []
        proofs: List[Dict[str, Any]] = []
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
            for finding in run_checks(combined_text, check_dir, gadgets, chains):
                findings.append({
                    "name": finding.name,
                    "status": finding.status,
                    "evidence": finding.evidence,
                    "details": finding.details,
                })
        if args.mode == "poc":
            runner_results = []
            for runner_path in args.poc_runner:
                runner = load_runner(Path(runner_path))
                token = uuid.uuid4().hex
                callback_url = f"{callback_base}/?token={token}" if callback_base else None
                ctx = {
                    "run_id": run_id,
                    "callback_url": callback_url,
                    "callback_token": token,
                    "verifier": args.verifier,
                }
                target = {"host": endpoint.host, "port": endpoint.port, "kind": endpoint.kind}
                payload_spec = {
                    "proof": args.poc_proof,
                    "file_path": render_file_path(args.poc_file_path),
                    "file_template": args.poc_file_template,
                }
                raw_result = run_runner(runner, ctx, target, payload_spec)
                result = coerce_runner_result(raw_result)
                runner_evidence = write_evidence_json(
                    evidence_dir / endpoint.endpoint_id,
                    f"runner-{runner.runner_id}.json",
                    {
                        "runner_id": runner.runner_id,
                        "title": runner.title,
                        "success": result.success,
                        "notes": result.notes,
                        "evidence_refs": result.evidence_refs,
                    },
                )
                runner_results.append({
                    "runner_id": runner.runner_id,
                    "title": runner.title,
                    "success": result.success,
                    "evidence": [runner_evidence],
                })

                verifier_ctx = VerifierContext(
                    evidence_dir=evidence_dir / endpoint.endpoint_id,
                    verifier=args.verifier,
                    callback_registry=callback_server.registry if callback_server else None,
                    callback_timeout=args.callback_timeout,
                    smb_share_path=smb_share_path,
                    smb_share_subdir=args.smb_share_subdir,
                )
                proofs_to_run = [args.poc_proof] if args.poc_proof != "both" else ["filewrite", "cmd"]
                for proof_type in proofs_to_run:
                    if proof_type == "filewrite":
                        proof_path = render_file_path(args.poc_file_path)
                        verify_result = verify_file_write(
                            verifier_ctx,
                            result.execution_channel,
                            proof_path,
                            args.poc_file_template,
                            parse_bool(args.poc_cleanup),
                        )
                        proofs.append({
                            "type": "FileWrite",
                            "path": proof_path,
                            "verified": verify_result.verified,
                            "artifacts": verify_result.artifacts,
                            "evidence": verify_result.evidence_refs,
                            "summary": "file-write proof" if verify_result.verified else "not verified",
                        })
                    elif proof_type == "cmd":
                        verify_result = verify_cmd(
                            verifier_ctx,
                            result.execution_channel,
                            "whoami/hostname",
                        )
                        proofs.append({
                            "type": "CommandOutput",
                            "path": None,
                            "verified": verify_result.verified,
                            "artifacts": verify_result.artifacts,
                            "evidence": verify_result.evidence_refs,
                            "summary": "command output proof" if verify_result.verified else "not verified",
                        })
            poc_payload = {"proofs": proofs, "runners": runner_results}
        else:
            poc_payload = {}

        exploitability = compute_exploitability(findings, proofs) if args.mode == "poc" else compute_exploitability(findings, [])
        return {
            "endpoint_id": endpoint.endpoint_id,
            "host": endpoint.host,
            "port": endpoint.port,
            "kind": endpoint.kind,
            "enum": enum_data,
            "findings": findings,
            "poc": poc_payload,
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
