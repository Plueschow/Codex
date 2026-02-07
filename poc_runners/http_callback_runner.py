import json
import os
import shlex
import subprocess
from typing import Any, Dict

RUNNER_ID = "http-callback"
TITLE = "HTTP Callback Runner (external command wrapper)"


def _format_command(template: str, ctx: Dict[str, Any], target: Dict[str, Any], payload_spec: Dict[str, Any]) -> str:
    replacements = {
        "{HOST}": target.get("host", ""),
        "{PORT}": str(target.get("port", "")),
        "{CALLBACK_URL}": ctx.get("callback_url") or "",
        "{CALLBACK_TOKEN}": ctx.get("callback_token") or "",
        "{FILE_PATH}": payload_spec.get("file_path", ""),
        "{PROOF}": payload_spec.get("proof", ""),
    }
    for key, value in replacements.items():
        template = template.replace(key, value)
    return template


async def run(ctx: Dict[str, Any], target: Dict[str, Any], payload_spec: Dict[str, Any]) -> Dict[str, Any]:
    command_template = os.environ.get("RJSCAN_RUNNER_CMD")
    result_file = os.environ.get("RJSCAN_RUNNER_RESULT")

    if result_file:
        data = json.loads(open(result_file, "r", encoding="utf-8").read())
        return data

    if not command_template:
        return {
            "success": False,
            "execution_channel": {},
            "evidence_refs": [],
            "notes": ["No RJSCAN_RUNNER_CMD or RJSCAN_RUNNER_RESULT provided."],
        }

    command = _format_command(command_template, ctx, target, payload_spec)
    completed = subprocess.run(shlex.split(command), capture_output=True, text=True, timeout=120)

    return {
        "success": completed.returncode == 0,
        "execution_channel": {
            "callback_token": ctx.get("callback_token"),
        },
        "evidence_refs": [],
        "notes": [
            f"exit_code={completed.returncode}",
            "stdout=" + completed.stdout.strip(),
            "stderr=" + completed.stderr.strip(),
        ],
    }
