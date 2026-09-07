"""
Falsifiability pass. Every test here plants a failure and requires the suite to
notice, or plants a distractor and requires the suite NOT to move.

A suite whose vectors all pass on first run has demonstrated nothing. These are
the runs that decide whether the vectors are load bearing or decorative.
"""
import base64, copy, json, os, subprocess, sys

from wil.level import grade_set, grade_one, OperatorGraph, W0, W1, W2, WU, W3, W4, ORDER
from wil.resolve import AnchorStore, controller_of

HERE = os.path.dirname(os.path.abspath(__file__))
STORE = AnchorStore(os.path.join(HERE, "anchors/trust-set.json"))
GRAPH = OperatorGraph(json.load(open(os.path.join(HERE, "anchors/operator-graph.json"))))

PASS, FAIL = [], []


def check(name, condition, detail=""):
    (PASS if condition else FAIL).append(name)
    print(f"  {'ok  ' if condition else 'FAIL'}  {name}" + (f"   {detail}" if detail and not condition else ""))


def load(vec):
    with open(os.path.join(HERE, "vectors", vec + ".json")) as fh:
        return json.load(fh)


def level_of(vec_doc, graph=GRAPH):
    return grade_set(vec_doc["attestations"], STORE, graph)["set_level"]


print("\n== planted failures: the suite must go red ==")

# --- P1: naive implementation that counts distinct kid values ----------------
def grade_set_naive(receipts, store, graph):
    """The obvious wrong implementation. Counts distinct kid values as witnesses."""
    graded = [grade_one(r, store, graph) for r in receipts]
    indep = [g for g in graded if g["level"] == W3]
    kids = {g["kid"] for g in indep}
    top = W4 if len(kids) >= 2 else max((g["level"] for g in graded), default=W0)
    return {"set_level": top}

naive_a3 = grade_set_naive(load("A3-two-dids-one-domain")["attestations"], STORE, GRAPH)["set_level"]
check("A3 catches the count-distinct-kids implementation",
      naive_a3 == W4 and level_of(load("A3-two-dids-one-domain")) == W3,
      f"naive said {naive_a3}, correct said {level_of(load('A3-two-dids-one-domain'))}")

naive_a3b = grade_set_naive(load("A3b-declared-shared-root")["attestations"], STORE, GRAPH)["set_level"]
check("A3b catches an implementation that ignores declared shared roots",
      naive_a3b == W4 and level_of(load("A3b-declared-shared-root")) == W3,
      f"naive said {naive_a3b}")

# --- P2: tampered signature must drop to W0 ----------------------------------
tampered = copy.deepcopy(load("P1-independent")["attestations"][0])
raw = base64.urlsafe_b64decode(tampered["signature"] + "=" * (-len(tampered["signature"]) % 4))
tampered["signature"] = base64.urlsafe_b64encode(bytes([raw[0] ^ 0xFF]) + raw[1:]).decode().rstrip("=")
check("a flipped signature byte drops W3 to W0",
      grade_one(tampered, STORE, GRAPH)["level"] == W0,
      grade_one(tampered, STORE, GRAPH)["level"])

# --- P3: mutated payload must drop to W0 -------------------------------------
mutated = copy.deepcopy(load("P1-independent")["attestations"][0])
mutated["payload"]["decision"] = "allow"
check("flipping deny to allow after signing drops W3 to W0",
      grade_one(mutated, STORE, GRAPH)["level"] == W0)

# --- P4: swapping the anchor location must move the level --------------------
moved = copy.deepcopy(STORE)
moved.keys["witness-2026"] = dict(moved.keys["witness-2026"],
                                  served_from="https://agent.example/.well-known/jwks.json")
check("moving the witness key onto the subject's domain drops W3 to W1",
      grade_one(load("P1-independent")["attestations"][0], moved, GRAPH)["level"] == W1)

# --- P5: removing the operator declaration must move W2 to W3 ----------------
check("removing the operator graph does NOT promote W2 to W3",
      level_of(load("P2-operator"), OperatorGraph({})) == WU,
      level_of(load("P2-operator"), OperatorGraph({})))

check("removing the operator graph does NOT promote a W3 attestation either",
      level_of(load("P1-independent"), OperatorGraph({})) == WU,
      level_of(load("P1-independent"), OperatorGraph({})))

check("a corroborated set collapses to undetermined when nothing is declared",
      level_of(load("P3-corroborated"), OperatorGraph({})) == WU,
      level_of(load("P3-corroborated"), OperatorGraph({})))

# The defect this replaced: before the coverage requirement, an implementation
# that simply supplied no operator graph was awarded W3 for every attestation
# that was not literally self-anchored. A missing input produced the stronger
# verdict. This is the regression test for that.
check("no input combination lets silence reach W3 or above",
      all(ORDER.index(level_of(load(v), OperatorGraph({}))) < ORDER.index(W3)
          for v in ["P1-independent", "P2-operator", "P3-corroborated",
                    "A3-two-dids-one-domain", "A7-uncovered-controller"]))

print("\n== must not fire: distractors that must leave the level unchanged ==")

# --- N1: self-asserted independence fields have zero effect ------------------
a2 = level_of(load("A2-self-anchored"))
a4 = level_of(load("A4-declared-independence"))
check("A4 grades identically to A2 despite asserting W4 about itself",
      a2 == a4 == W1, f"A2={a2} A4={a4}")

# --- N2: a lying anchor_uri has zero effect ----------------------------------
check("A5 grades on where the key resolved, not on the anchor_uri it advertises",
      level_of(load("A5-anchor-claimed-not-fetched")) == W1)

# --- N3: chain length has zero effect ----------------------------------------
one = grade_set(load("A6-chained-self-attestation")["attestations"][:1], STORE, GRAPH)["set_level"]
eight = level_of(load("A6-chained-self-attestation"))
check("eight self-anchored receipts grade the same as one",
      one == eight == W1, f"1={one} 8={eight}")

# --- N4: an embedded key alongside a resolvable one changes nothing ----------
check("an embedded public_key next to a resolvable anchor does not move the level",
      level_of(load("A1-embedded-key")) == level_of(load("A2-self-anchored")) == W1)

# --- N5: reordering a set does not change the set level ----------------------
p3 = load("P3-corroborated")["attestations"]
check("reordering a corroborated set does not change its level",
      grade_set(p3, STORE, GRAPH)["set_level"] ==
      grade_set(list(reversed(p3)), STORE, GRAPH)["set_level"] == W4)

# --- N6: every result declares whether it rests on a declared input ----------
p1 = grade_set(load("P1-independent")["attestations"], STORE, GRAPH)
p2 = grade_set(load("P2-operator")["attestations"], STORE, GRAPH)
check("a W2 result is marked as resting on a declared input", p2["contains_declared_input"])
check("every check states the evidence it read",
      all(c["reads"] for a in p1["attestations"] for c in a["checks"]))

print("\n== format adapters: AIVS, draft-stone-aivs-00 ==")

import subprocess as _sp, tarfile, io
from wil.adapters import (read_aivs_bundle, aivs_to_attestation,
                          aivs_signature_holds, aivs_signing_profile)

BUNDLE = os.path.join(HERE, "out", "aivs_proof_demo.tar.gz")
if not os.path.exists(BUNDLE):
    _sp.run([sys.executable, os.path.join(HERE, "tools", "make_aivs_bundle.py"), BUNDLE],
            capture_output=True)

b = read_aivs_bundle(BUNDLE)
rec, _ = aivs_to_attestation(b)
empty = os.path.join(HERE, "out", "_st-empty.json")
os.makedirs(os.path.dirname(empty), exist_ok=True)
json.dump({"anchors": []}, open(empty, "w"))

check("a spec-conformant AIVS bundle recomputes its own chain hash",
      b["chain_hash_agrees"])
check("its Ed25519 signature verifies over the chain hash string",
      aivs_signature_holds(b)[0] is True)
check("and it still grades W0, because the key travels inside the archive",
      grade_one(rec, AnchorStore(empty), OperatorGraph({}),
                aivs_signing_profile())["level"] == W0)

# The remedy: the identical key, published outside the bundle.
ext = os.path.join(HERE, "out", "_st-external.json")
json.dump({"anchors": [{"served_from": "https://swarmsync.example/.well-known/jwks.json",
                        "keys": [{"kid": "aivs-session-key",
                                  "public_key_hex": b["public_key_hex"]}]}]},
          open(ext, "w"))
rec_ext = dict(rec, kid="aivs-session-key")
moved = grade_one(rec_ext, AnchorStore(ext), OperatorGraph({}), aivs_signing_profile())
check("publishing the same key outside the archive moves it off W0",
      moved["level"] != W0, moved["level"])
check("and does not move it past undetermined without a declaration",
      ORDER.index(moved["level"]) < ORDER.index(W3), moved["level"])

# A declared profile must not fall back to guessing.
wrong = grade_one(rec_ext, AnchorStore(ext), OperatorGraph({}),
                  ("deliberately-wrong", lambda r: b"not the signed bytes"))
check("a declared signing profile is not silently replaced by a guess",
      wrong["level"] == W0, wrong["level"])

# Tampering with a row must break the chain hash and therefore the signature.
tampered_rows = [dict(r) for r in b["rows"]]
tampered_rows[1]["row_hash"] = "0" * 64
from wil.adapters import aivs_chain_hash
check("altering a row hash changes the chain hash",
      aivs_chain_hash(tampered_rows) != b["chain_hash_computed"])

print("\n== A8: an anchor that looks independent and answers from home ==")

sys.path.insert(0, HERE)
from tools.redirect_fixture import Server, receipt as a8_receipt, WITNESS_URL, HONEST_URL, KID
from wil.live import LiveAnchorStore

try:
    with Server():
        r = a8_receipt()
        via_redirect = grade_one(r, LiveAnchorStore({KID: WITNESS_URL}),
                                 OperatorGraph({}))
        direct = grade_one(r, LiveAnchorStore({KID: HONEST_URL}), OperatorGraph({}))

    check("a receipt naming an independent issuer still grades W1 when its anchor "
          "redirects to the subject's own host",
          via_redirect["level"] == W1, via_redirect["level"])
    check("the recorded controller is where the anchor answered, not where it was asked",
          via_redirect["anchor_controller"] == f"localhost:8199",
          via_redirect["anchor_controller"])
    check("the same receipt and key, served without a redirect, does not grade W1",
          direct["level"] != W1, direct["level"])
    check("the receipt's own issuer field did not affect either level",
          r["issuer"] == "did:web:witness.test"
          and via_redirect["level"] != direct["level"])
except OSError as exc:
    check("A8 loopback server could bind", False, str(exc))

print("\n== the runner must return its verdict ==")
bad = os.path.join(HERE, "vectors", "_planted.json")
doc = load("A2-self-anchored"); doc["expect"] = "W4"
with open(bad, "w") as fh:
    json.dump(doc, fh)
try:
    rc = subprocess.run(["bash", os.path.join(HERE, "run.sh")],
                        capture_output=True, text=True).returncode
    check("run.sh exits non-zero when a vector does not match", rc != 0, f"exit={rc}")
finally:
    os.remove(bad)
rc = subprocess.run(["bash", os.path.join(HERE, "run.sh")],
                    capture_output=True, text=True).returncode
check("run.sh exits zero when every vector matches", rc == 0, f"exit={rc}")

# == --require is a strength threshold, and cannot be met by knowing less ==
#
# ORDER is one line from weakest to strongest, but W2? is not a strength. It
# records that independence was not determined. Mixing the two on one axis made
# the gate satisfiable by withholding evidence: the same receipts grade W2 with
# an operator graph and W2? without one, W2? sorts higher, and `--require W2?`
# therefore failed for the party who declared their operator relationships and
# passed for the party who did not. That is this tool's own argument backwards.

_bare = os.path.join(HERE, "vectors", "_require_probe.json")
with open(_bare, "w") as _fh:
    json.dump(json.load(open(os.path.join(HERE, "vectors",
                                          "P2-operator.json")))["attestations"],
              _fh)


def _cli(*extra):
    return subprocess.run(
        [sys.executable, "-m", "wil.cli", _bare,
         "--trust-set", os.path.join(HERE, "anchors/trust-set.json")]
        + list(extra),
        capture_output=True, text=True, cwd=HERE).returncode


_graph = ["--operator-graph", os.path.join(HERE, "anchors/operator-graph.json")]

try:
    _with = _cli(*(_graph + ["--require", "W2?"]))
    _without = _cli("--require", "W2?")
    check("requiring W2? is refused rather than gated",
          _with == 2 and _without == 2, f"with={_with} without={_without}")
    check("withholding the operator graph cannot pass a gate that supplying it "
          "fails", _with == _without, f"with={_with} without={_without}")

    _diverged = [lv for lv in ("W0", "W1", "W2", "W3", "W4")
                 if _cli(*(_graph + ["--require", lv])) != _cli("--require", lv)]
    check("no strength threshold changes when the operator graph is withheld",
          not _diverged, f"diverged at {_diverged}")

    _bad = _cli("--require", "W9")
    check("an unknown level is refused with a message, not a traceback",
          _bad == 2, f"exit={_bad}")

    check("a threshold the set clears still passes",
          _cli(*(_graph + ["--require", "W2"])) == 0)
    check("a threshold the set does not clear still fails",
          _cli(*(_graph + ["--require", "W3"])) == 1)
finally:
    os.remove(_bare)


print(f"\n{len(PASS)} passed, {len(FAIL)} failed")
if FAIL:
    for f in FAIL:
        print("  failed: " + f)
    sys.exit(1)
