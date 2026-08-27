"""Grade an AIVS bundle. Run: python3 tools/grade_aivs.py <bundle.tar.gz>"""
import json, os, sys
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from wil.adapters import (read_aivs_bundle, aivs_to_attestation,
                          aivs_signature_holds, aivs_signing_profile)
from wil.level import grade_one, OperatorGraph
from wil.resolve import AnchorStore

path = sys.argv[1]
anchors = sys.argv[2] if len(sys.argv) > 2 else None

b = read_aivs_bundle(path)
receipt, facts = aivs_to_attestation(b)
sig_ok, sig_how = aivs_signature_holds(b)

print(f"AIVS bundle: {os.path.basename(path)}")
print(f"  members present : {b['members_present']}")
print(f"  missing         : {b['members_missing'] or 'none'}")
print(f"  chain hash       : {b['chain_hash_computed'][:24]}...")
print(f"  agrees with manifest and session_sig.txt: {b['chain_hash_agrees']}")
print(f"  signature over the chain hash: {sig_ok}   ({sig_how})")
print()
for f in facts:
    print(f"  [{f.kind}] {f.name} = {f.value}")
print()

# Grade with an empty trust set, which is the honest default: nothing in this
# format tells a verifier where else the key could be found.
empty = os.path.join(os.path.dirname(__file__), "..", "out", "_empty-trust-set.json")
json.dump({"anchors": []}, open(empty, "w"))
g = grade_one(receipt, AnchorStore(empty), OperatorGraph({}), aivs_signing_profile())
print(f"  WIL level: {g['level']}  {g['label']}")
print(f"  {g['reason']}")
print()
print("  What this does and does not say:")
print("    Section 8.1 of the draft claims integrity, completeness and ordering.")
print("    Every one of those held on this bundle: the chain recomputes, all three")
print("    copies of the chain hash agree, and the signature verifies. WIL does not")
print("    grade any of that and is not disputing it.")
print("    Section 8.2 says 'The public key in the bundle is self-asserted.' W0 is")
print("    that sentence expressed as a level, on a bundle built to the spec.")
print()
if anchors:
    # Give the receipt a kid so the same key can be found outside the archive.
    receipt["kid"] = "aivs-session-key"
    g2 = grade_one(receipt, AnchorStore(anchors), OperatorGraph({}), aivs_signing_profile())
    print(f"  Same bundle, same key, published at a well-known endpoint instead of")
    print(f"  carried inside the archive: {g2['level']}  {g2['label']}")
    print(f"    {g2['reason']}")
    print()
    print("  The bundle bytes are unchanged. What changed is where a verifier can")
    print("  find the key. That is the whole distance between W0 and the rest of the")
    print("  ladder, and closing it is a publishing step rather than a format change.")
