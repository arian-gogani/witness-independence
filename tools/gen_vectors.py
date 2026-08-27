"""Generate the WIL conformance vectors with real Ed25519 signatures."""
import json, os, base64, hashlib
from nacl.signing import SigningKey

OUT = os.path.join(os.path.dirname(__file__), "..", "vectors")
ANCH = os.path.join(os.path.dirname(__file__), "..", "anchors")
os.makedirs(OUT, exist_ok=True); os.makedirs(ANCH, exist_ok=True)

def jcs(o):
    return json.dumps(o, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()

def b64u(b):
    return base64.urlsafe_b64encode(b).decode().rstrip("=")

def key(seedname):
    sk = SigningKey(hashlib.sha256(seedname.encode()).digest())
    return sk, sk.verify_key.encode().hex()

SUBJECT = "did:web:agent.example"

# kid -> (seed name, served_from)
KEYS = {
    "agent-self-2026":  ("agent.example",    "https://agent.example/.well-known/jwks.json"),
    "platform-2026":    ("platform.example", "https://platform.example/.well-known/jwks.json"),
    "witness-2026":     ("witness.example",  "https://witness.example/.well-known/jwks.json"),
    "observer-2026":    ("observer.example", "https://observer.example/.well-known/jwks.json"),
    "alpha-2026":       ("alpha",            "https://shared.example/.well-known/jwks.json"),
    "beta-2026":        ("beta",             "https://shared.example/.well-known/jwks.json"),
    "gamma-2026":       ("gamma",            "https://gamma.example/.well-known/jwks.json"),
    "delta-2026":       ("delta",            "https://delta.example/.well-known/jwks.json"),
}

signers, anchors = {}, {}
for kid, (seed, served) in KEYS.items():
    sk, pub = key(seed)
    signers[kid] = sk
    anchors.setdefault(served, []).append({"kid": kid, "public_key_hex": pub})

with open(os.path.join(ANCH, "trust-set.json"), "w") as fh:
    json.dump({
        "note": "Offline stand-in for live JWKS and DID resolution. served_from is the "
                "location the resolver would have fetched the key from; the level is "
                "computed from that location, never from a field inside a receipt.",
        "anchors": [{"served_from": url, "keys": ks} for url, ks in sorted(anchors.items())],
    }, fh, indent=2)

def receipt(kid, subject=SUBJECT, extra_payload=None, extra_top=None, seq=0):
    payload = {
        "type": "decision_receipt",
        "subject": subject,
        "action": {"kind": "Bash", "target": "rm -rf /tmp/scratch"},
        "decision": "deny",
        "policy_id": "autoresearch-safe",
        "sequence": seq,
        "timestamp": "2026-08-26T00:00:00Z",
    }
    if extra_payload:
        payload.update(extra_payload)
    sig = signers[kid].sign(jcs(payload)).signature
    r = {"v": 2, "type": "decision_receipt", "algorithm": "ed25519",
         "kid": kid, "issued_at": "2026-08-26T00:00:00Z",
         "payload": payload, "signature": b64u(sig)}
    if extra_top:
        r.update(extra_top)
    return r

def write(name, obj, expect, why):
    path = os.path.join(OUT, name + ".json")
    with open(path, "w") as fh:
        json.dump({"expect": expect, "why": why,
                   "attestations": obj if isinstance(obj, list) else [obj]}, fh, indent=2)
    return name

cases = []

# ---- positives ---------------------------------------------------------------
cases.append(write("P1-independent", receipt("witness-2026"), "W3",
    "key resolves from witness.example, which is neither the subject nor a "
    "declared operator of it"))

cases.append(write("P2-operator", receipt("platform-2026"), "W2",
    "key resolves from platform.example, declared in the operator graph as "
    "operating the subject"))

cases.append(write("P3-corroborated",
    [receipt("witness-2026"), receipt("observer-2026")], "W4",
    "two independent attestations over the same action resting on two distinct roots"))

# ---- adversarial -------------------------------------------------------------
emb = receipt("agent-self-2026")
emb["public_key"] = "b1f0" * 16
cases.append(write("A1-embedded-key", emb, "W1",
    "the envelope also carries a public_key field; the level must come from where "
    "the key actually resolved, and the embedded field must not raise or lower it"))

emb_only = receipt("agent-self-2026")
emb_only["kid"] = "not-in-any-anchor"
emb_only["public_key"] = "b1f0" * 16
cases.append(write("A1b-embedded-key-only", emb_only, "W0",
    "the only verification key available is inside the envelope; the ACTA draft "
    "forbids trusting it, so nothing is attested"))

cases.append(write("A2-self-anchored", receipt("agent-self-2026"), "W1",
    "a well formed anchor at a well known path with a correct kid and a valid "
    "signature, served by the subject's own domain; this is the case that passes "
    "every published check in the ecosystem today"))

cases.append(write("A3-two-dids-one-domain",
    [receipt("alpha-2026"), receipt("beta-2026")], "W3",
    "two distinct kid values, two attestations, one controller; an implementation "
    "that counts distinct kid values reaches W4 here and is wrong"))

cases.append(write("A3b-declared-shared-root",
    [receipt("gamma-2026"), receipt("delta-2026")], "W3",
    "two controllers on distinct domains that the operator graph declares share a "
    "root; the transitive closure must collapse them to one witness"))

cases.append(write("A4-declared-independence",
    receipt("agent-self-2026", extra_payload={
        "witness_independence": "W4", "third_party": True, "self_attested": False}),
    "W1",
    "the receipt asserts its own independence in three separate fields; the level "
    "must be identical to A2, which is the same receipt without them"))

lying = receipt("agent-self-2026", extra_payload={
    "anchor_uri": "https://witness.example/.well-known/jwks.json"})
cases.append(write("A5-anchor-claimed-not-fetched", lying, "W1",
    "anchor_uri points at an independent domain but the key resolved from the "
    "subject's own; grading must follow the resolution, not the claim"))

chain = [receipt("agent-self-2026", seq=i) for i in range(8)]
cases.append(write("A6-chained-self-attestation", chain, "W1",
    "eight valid self-anchored receipts in sequence; chain length must not raise "
    "the level, because volume of self-attestation is still self-attestation"))

cases.append(write("A7-uncovered-controller", receipt("witness-2026"), "W2?",
    "the same attestation as P1, graded against an operator graph that says nothing "
    "about witness.example; the level must fall to undetermined rather than rise to "
    "W3, because a missing input must never produce the stronger verdict. This vector "
    "exists because the first implementation of this tool got it wrong in exactly "
    "that direction. It is run against anchors/operator-graph-silent.json."))

# ---- operator graphs ---------------------------------------------------------
SUBJ_KEYS = ["did:web:agent.example", "agent.example"]

with open(os.path.join(ANCH, "operator-graph.json"), "w") as fh:
    json.dump({
        "declared_by": "wil-vector-fixture",
        "note": "Every fact in this file is operator declared. No run establishes it. "
                "independent_of is required to reach W3: independence has to be claimed "
                "by somebody, because a graph that stays silent about a controller has "
                "not shown that controller to be independent.",
        "operates": {"platform.example": SUBJ_KEYS},
        "independent_of": {c: SUBJ_KEYS for c in [
            "witness.example", "observer.example", "shared.example",
            "gamma.example", "delta.example"]},
        "shared_roots": [["gamma.example", "delta.example"]],
    }, fh, indent=2)

with open(os.path.join(ANCH, "operator-graph-silent.json"), "w") as fh:
    json.dump({
        "declared_by": "wil-vector-fixture",
        "note": "Deliberately empty. Used only by A7, to establish that silence about a "
                "controller does not award independence.",
        "operates": {},
        "independent_of": {},
        "shared_roots": [],
    }, fh, indent=2)

print(f"wrote {len(cases)} vectors and 3 anchor files")
for c in cases:
    print("  " + c)
