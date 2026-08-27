"""
Build an AIVS proof bundle exactly to draft-stone-aivs-00, so the grading below
is of the format as specified rather than of a strawman.
"""
import base64, hashlib, io, json, os, sys, tarfile, time
from nacl.signing import SigningKey

OUT = sys.argv[1] if len(sys.argv) > 1 else "out/aivs_proof_demo.tar.gz"
os.makedirs(os.path.dirname(OUT) or ".", exist_ok=True)

sk = SigningKey(hashlib.sha256(b"aivs-demo-agent").digest())
pub = sk.verify_key.encode()

SESSION = "sess-abc123"
rows, prev = [], ""
actions = [
    ("tool_call", "browser.navigate", {"url": "https://example.com"}, {"title": "Example Domain"}),
    ("tool_call", "fs.read",          {"path": "/tmp/notes.md"},      {"bytes": 812}),
    ("tool_call", "shell.exec",       {"cmd": "rm -rf /tmp/scratch"}, {"status": "blocked"}),
]
for i, (atype, tool, inp, outp) in enumerate(actions, start=1):
    row = {
        "id": i, "session_id": SESSION, "action_type": atype, "tool_name": tool,
        "inputs_json": json.dumps(inp), "outputs_json": json.dumps(outp),
        "cost_cents": 0, "error": "", "timestamp": 1710252645.123456 + i,
        "prev_hash": prev,
    }
    material = json.dumps({k: row[k] for k in (
        "id", "session_id", "action_type", "tool_name", "inputs_json",
        "outputs_json", "cost_cents", "error", "timestamp", "prev_hash")},
        sort_keys=True, separators=(",", ":"))
    row["row_hash"] = hashlib.sha256(material.encode()).hexdigest()
    prev = row["row_hash"]
    rows.append(row)

chain_hash = hashlib.sha256("".join(r["row_hash"] for r in rows).encode("utf-8")).hexdigest()
sig_b64 = base64.b64encode(sk.sign(chain_hash.encode("utf-8")).signature).decode()

manifest = {
    "session_id": SESSION, "exported_at": "2026-08-27T00:00:00Z",
    "action_count": len(rows), "chain_hash": chain_hash, "aivs_version": "1.0",
    "generator": "ExampleAgent",
    "generator_url": "https://github.com/example/agent",
}
sig_txt = f"chain_hash:{chain_hash}\nsignature:{sig_b64}\n"
pem = ("-----BEGIN PUBLIC KEY-----\n"
       + base64.encodebytes(bytes.fromhex("302a300506032b6570032100") + pub).decode()
       + "-----END PUBLIC KEY-----\n")
verify_py = "# embedded verifier, stdlib only, per section 6 of the draft\n"

files = {
    "session_proof/audit_log.jsonl": "\n".join(json.dumps(r) for r in rows) + "\n",
    "session_proof/manifest.json": json.dumps(manifest, indent=2),
    "session_proof/session_sig.txt": sig_txt,
    "session_proof/public_key.pem": pem,
    "session_proof/verify.py": verify_py,
}
with tarfile.open(OUT, "w:gz") as tf:
    for name, content in files.items():
        data = content.encode()
        info = tarfile.TarInfo(name)
        info.size = len(data)
        info.mtime = 0
        tf.addfile(info, io.BytesIO(data))

print("wrote", OUT)
print("chain_hash:", chain_hash)
print("public key inside the bundle:", pub.hex())
