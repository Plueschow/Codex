from pathlib import Path
import urllib.request

from rjscan.callback import CallbackServer
from rjscan.poc.verifier_windows import VerifierContext, verify_cmd, verify_file_write


def test_verify_cmd_exec_channel(tmp_path):
    ctx = VerifierContext(
        evidence_dir=tmp_path,
        verifier="auto",
        callback_registry=None,
        callback_timeout=1.0,
        smb_share_path=None,
        smb_share_subdir=None,
    )
    exec_channel = {"cmd_output": {"whoami": "user", "hostname": "HOST"}}
    result = verify_cmd(ctx, exec_channel, "whoami/hostname")
    assert result.verified is True
    assert result.evidence_refs


def test_verify_file_write_smb(tmp_path):
    share = tmp_path / "share"
    subdir = "run"
    (share / subdir).mkdir(parents=True)
    proof_path = "C:\\Pentest_RMI_2026-02-07.txt"
    proof_file = share / subdir / Path(proof_path).name
    proof_file.write_text("proof")
    ctx = VerifierContext(
        evidence_dir=tmp_path,
        verifier="smb_share",
        callback_registry=None,
        callback_timeout=1.0,
        smb_share_path=share,
        smb_share_subdir=subdir,
    )
    exec_channel = {"smb_relpath": f"{subdir}/{proof_file.name}"}
    result = verify_file_write(ctx, exec_channel, proof_path, "content", cleanup=False)
    assert result.verified is True
    assert result.evidence_refs


def test_verify_file_write_callback(tmp_path):
    server = CallbackServer("127.0.0.1", 0)
    server.start()
    try:
        token = "token123"
        url = f"{server.address}/?token={token}"
        urllib.request.urlopen(url).read()
        ctx = VerifierContext(
            evidence_dir=tmp_path,
            verifier="callback_http",
            callback_registry=server.registry,
            callback_timeout=1.0,
            smb_share_path=None,
            smb_share_subdir=None,
        )
        exec_channel = {"callback_token": token}
        result = verify_file_write(ctx, exec_channel, "C:\\file.txt", "content", cleanup=False)
        assert result.verified is True
        assert result.evidence_refs
    finally:
        server.stop()
