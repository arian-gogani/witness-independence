"""
Adapters that turn other people's artifact formats into the evidence shape this
tool grades. Each adapter answers three questions and nothing else:

  who is the artifact about, where did the verification key come from, and does
  the signature hold over the bytes that format actually signs.

An adapter never invents a level and never reads an independence claim.
"""
import base64
import hashlib
import json
import os
import tarfile
from typing import Any, Dict, List, Optional, Tuple

from .evidence import Fact, OBSERVED, ABSENT


# ---------------------------------------------------------------------------
# AIVS, draft-stone-aivs-00
# ---------------------------------------------------------------------------
#
# A bundle is a gzip tar containing audit_log.jsonl, manifest.json,
# session_sig.txt, public_key.pem and verify.py. The signature covers the
# chain hash, which is SHA-256 over the concatenated row hashes, or over the
# bytes "empty" for an empty log. The verification key travels in the bundle
# as public_key.pem.
#
# Section 8.2 of the draft states the consequence itself: "The public key in
# the bundle is self-asserted."

AIVS_MEMBERS = ("audit_log.jsonl", "manifest.json", "session_sig.txt",
                "public_key.pem", "verify.py")


def _member(tf: tarfile.TarFile, name: str) -> Optional[bytes]:
    for m in tf.getmembers():
        if os.path.basename(m.name) == name and m.isfile():
            fh = tf.extractfile(m)
            if fh:
                return fh.read()
    return None


def aivs_chain_hash(rows: List[Dict[str, Any]]) -> str:
    if not rows:
        return hashlib.sha256(b"empty").hexdigest()
    combined = "".join(r.get("row_hash", "") for r in rows)
    return hashlib.sha256(combined.encode("utf-8")).hexdigest()


def read_aivs_bundle(path: str) -> Dict[str, Any]:
    """Return the evidence an AIVS bundle actually carries."""
    out: Dict[str, Any] = {"format": "aivs", "path": path, "problems": []}
    with tarfile.open(path, "r:gz") as tf:
        present = {os.path.basename(m.name) for m in tf.getmembers() if m.isfile()}
        out["members_present"] = sorted(present & set(AIVS_MEMBERS))
        out["members_missing"] = sorted(set(AIVS_MEMBERS) - present)

        raw_log = _member(tf, "audit_log.jsonl")
        rows = []
        if raw_log:
            for line in raw_log.decode().splitlines():
                line = line.strip()
                if line:
                    rows.append(json.loads(line))
        out["rows"] = rows

        raw_man = _member(tf, "manifest.json")
        out["manifest"] = json.loads(raw_man.decode()) if raw_man else None

        raw_sig = _member(tf, "session_sig.txt")
        sig_doc = {}
        if raw_sig:
            for line in raw_sig.decode().splitlines():
                if ":" in line:
                    k, v = line.split(":", 1)
                    sig_doc[k.strip()] = v.strip()
        out["sig_doc"] = sig_doc

        pem = _member(tf, "public_key.pem")
        out["public_key_pem_present"] = pem is not None
        out["public_key_hex"] = _ed25519_hex_from_pem(pem) if pem else None

    computed = aivs_chain_hash(rows)
    out["chain_hash_computed"] = computed
    out["chain_hash_manifest"] = (out["manifest"] or {}).get("chain_hash")
    out["chain_hash_sig_doc"] = sig_doc.get("chain_hash")
    out["chain_hash_agrees"] = (
        computed == out["chain_hash_manifest"] == out["chain_hash_sig_doc"])
    return out


def _ed25519_hex_from_pem(pem: bytes) -> Optional[str]:
    """
    Pull the 32 raw bytes out of an Ed25519 SubjectPublicKeyInfo PEM without a
    crypto library: the DER prefix for Ed25519 SPKI is fixed at 12 bytes.
    """
    try:
        body = b"".join(l for l in pem.splitlines()
                        if not l.startswith(b"-----"))
        der = base64.b64decode(body)
        prefix = bytes.fromhex("302a300506032b6570032100")
        if der.startswith(prefix) and len(der) == len(prefix) + 32:
            return der[len(prefix):].hex()
    except Exception:
        pass
    return None


def aivs_to_attestation(bundle: Dict[str, Any]) -> Tuple[Dict[str, Any], List[Fact]]:
    """
    Express an AIVS bundle in the shape grade_one reads.

    The key travels inside the archive, so the receipt is given the key in an
    envelope field. That is not a criticism smuggled into an adapter: it is
    where the format puts it, and the draft says so in section 8.2.
    """
    man = bundle.get("manifest") or {}
    subject = man.get("generator_url") or man.get("generator") or man.get("session_id")
    receipt = {
        "v": "aivs-1.0",
        "type": "aivs_session_proof",
        "algorithm": "ed25519",
        "issuer": subject,
        "payload": {
            "type": "aivs_session_proof",
            "subject": subject,
            "session_id": man.get("session_id"),
            "action_count": man.get("action_count"),
            "chain_hash": bundle.get("chain_hash_computed"),
            "exported_at": man.get("exported_at"),
        },
        # The bundle's own key, carried with the artifact.
        "public_key": bundle.get("public_key_hex"),
        "signature": bundle.get("sig_doc", {}).get("signature"),
    }
    facts = [
        Fact("aivs.members", bundle.get("members_present"), OBSERVED,
             "files actually present in the tar archive"),
        Fact("aivs.chain_hash_recomputed", bundle.get("chain_hash_computed"), OBSERVED,
             "SHA-256 over the concatenated row_hash values, per the draft"),
        Fact("aivs.chain_hash_agrees", bundle.get("chain_hash_agrees"), OBSERVED,
             "whether the recomputed chain hash matches manifest.json and session_sig.txt"),
        Fact("aivs.key_location",
             "public_key.pem, inside the bundle" if bundle.get("public_key_pem_present")
             else None,
             OBSERVED if bundle.get("public_key_pem_present") else ABSENT,
             "where the verification key travels in this format"),
    ]
    return receipt, facts


def aivs_signature_holds(bundle: Dict[str, Any]) -> Tuple[Optional[bool], str]:
    """Ed25519 over the chain hash string, per the draft."""
    try:
        from nacl.signing import VerifyKey
        from nacl.exceptions import BadSignatureError
    except ImportError:
        return None, "pynacl not installed"
    pk = bundle.get("public_key_hex")
    sig_b64 = bundle.get("sig_doc", {}).get("signature")
    ch = bundle.get("chain_hash_computed")
    if not (pk and sig_b64 and ch):
        return False, "bundle is missing a key, a signature, or a chain hash"
    try:
        VerifyKey(bytes.fromhex(pk)).verify(ch.encode("utf-8"),
                                            base64.b64decode(sig_b64))
        return True, "Ed25519 over the chain hash string, using the key inside the bundle"
    except BadSignatureError:
        return False, "signature does not verify over the recomputed chain hash"
    except Exception as exc:
        return False, f"could not check: {exc}"


def aivs_signing_profile():
    """
    What an AIVS bundle signs: the chain hash, as a UTF-8 string.

    Per the draft: signature_bytes = Ed25519_Sign(private_key,
    chain_hash.encode("utf-8")). It is neither of the canonical scopes the ACTA
    receipts use, which is exactly why an adapter has to say so rather than let
    a verifier guess.
    """
    def signed_bytes(receipt):
        return (receipt.get("payload", {}).get("chain_hash") or "").encode("utf-8")
    return ("aivs-chain-hash-utf8", signed_bytes)
