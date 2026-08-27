"""
Grade artifacts that actually exist, starting with the ones this measurement is
least flattering to.

A measurement that is only ever run on fixtures is a fixture. This runs WIL over
the reference receipts shipped by ScopeBlind/agent-governance-testvectors and over
a receipt built the way Nobulex documents that it builds them.
"""
import base64, glob, json, os, subprocess, sys
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from wil.level import grade_one, grade_set, OperatorGraph
from wil.resolve import AnchorStore

TV = "/tmp/tv"
OUT = os.path.join(os.path.dirname(__file__), "..", "out")
os.makedirs(OUT, exist_ok=True)

# Build a trust set from the JWKS files that actually ship in that repository,
# recording where each one really sits. No external endpoint is involved,
# because the repository does not publish one.
anchors = []
for jf in sorted(glob.glob(os.path.join(TV, "aps-gateway-enforcement", "**", "jwks.json"),
                           recursive=True)):
    doc = json.load(open(jf))
    keys = []
    for k in doc.get("keys", []):
        x = k.get("x")
        if not x:
            continue
        pad = "=" * (-len(x) % 4)
        keys.append({"kid": k.get("kid"),
                     "public_key_hex": base64.urlsafe_b64decode(x + pad).hex()})
    if keys:
        rel = os.path.relpath(jf, TV)
        anchors.append({"served_from": "file:" + rel, "keys": keys})

ts_path = os.path.join(OUT, "real-trust-set.json")
json.dump({"note": "Built from the JWKS files that ship inside the repository. "
                   "served_from records where each key actually sits, which is "
                   "beside the receipt it verifies, not at any published endpoint.",
           "anchors": anchors}, open(ts_path, "w"), indent=2)

store = AnchorStore(ts_path)
graph = OperatorGraph({})   # nobody has declared anything about these parties

rows = []
for rf in sorted(glob.glob(os.path.join(TV, "aps-gateway-enforcement", "*", "receipt.json"))):
    r = json.load(open(rf))
    g = grade_one(r, store, graph)
    rows.append({
        "artifact": os.path.relpath(rf, TV),
        "issuer_field": r.get("issuer"),
        "subject_found": g["subject"],
        "level": g["level"],
        "label": g["label"],
        "reason": g["reason"],
        "anchor_controller": g["anchor_controller"],
    })

# A receipt built the way Nobulex documents that it builds them. The crosswalk
# aeoess publishes about Nobulex states: "The evaluator_did equals the agentDid
# (self-evaluated)". So the issuer and the subject are one identifier.
from nacl.signing import SigningKey
import hashlib
def jcs(o): return json.dumps(o, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()
def b64u(b): return base64.urlsafe_b64encode(b).decode().rstrip("=")

AGENT = "did:web:agent.nobulex.example"
sk = SigningKey(hashlib.sha256(b"nobulex-agent").digest())
payload = {"type": "decision_receipt", "subject": AGENT, "agent_id": AGENT,
           "evaluator_did": AGENT, "action": {"kind": "Bash", "target": "curl example.com"},
           "decision": "allow", "sequence": 0, "timestamp": "2026-08-26T00:00:00Z"}
nb = {"v": 2, "type": "decision_receipt", "algorithm": "ed25519",
      "kid": "nobulex-agent-2026", "issuer": AGENT,
      "issued_at": "2026-08-26T00:00:00Z", "payload": payload,
      "signature": b64u(sk.sign(jcs(payload)).signature)}

nb_ts = os.path.join(OUT, "nobulex-trust-set.json")
json.dump({"note": "The agent publishes its own JWKS at its own well-known path, "
                   "which satisfies the ACTA external-anchoring rule in full.",
           "anchors": [{"served_from": "https://agent.nobulex.example/.well-known/jwks.json",
                        "keys": [{"kid": "nobulex-agent-2026",
                                  "public_key_hex": sk.verify_key.encode().hex()}]}]},
          open(nb_ts, "w"), indent=2)
json.dump(nb, open(os.path.join(OUT, "nobulex-receipt.json"), "w"), indent=2)

gnb = grade_one(nb, AnchorStore(nb_ts), graph)
rows.append({"artifact": "nobulex, built as its published crosswalk describes",
             "issuer_field": nb["issuer"], "subject_found": gnb["subject"],
             "level": gnb["level"], "label": gnb["label"], "reason": gnb["reason"],
             "anchor_controller": gnb["anchor_controller"]})

json.dump(rows, open(os.path.join(OUT, "real-grading.json"), "w"), indent=2)

w = max(len(r["artifact"]) for r in rows)
print(f"{'ARTIFACT'.ljust(w)}  LEVEL  LABEL")
print("-" * (w + 40))
for r in rows:
    print(f"{r['artifact'].ljust(w)}  {r['level']:<5}  {r['label']}")
print()
for r in rows:
    print(f"* {r['artifact']}")
    print(f"    issuer field: {r['issuer_field']}")
    print(f"    subject read: {r['subject_found']}")
    print(f"    anchor controller: {r['anchor_controller']}")
    print(f"    {r['reason']}")
    print()
