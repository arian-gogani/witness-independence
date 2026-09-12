"""
Key resolution. The output of this module is the load-bearing evidence for the
whole measurement: not where a receipt SAYS its key lives, but where the key was
actually retrieved from, and who controls that place.
"""
import json
import os
import re
from typing import Dict, Any, Optional, Tuple
from urllib.parse import urlparse

from .evidence import Fact, OBSERVED, ABSENT

# Field names the ACTA draft names explicitly as keys that must not be trusted
# when carried inside the envelope.
EMBEDDED_KEY_FIELDS = (
    "public_key", "publicKey", "pubkey", "verification_key",
    "verification_jwk", "verificationKey", "jwk",
)


def find_embedded_key(receipt: Dict[str, Any]) -> Optional[str]:
    """Return the first embedded verification key found anywhere in the receipt."""
    def walk(node):
        if isinstance(node, dict):
            for k, v in node.items():
                if k in EMBEDDED_KEY_FIELDS and isinstance(v, (str, dict)):
                    return k
                r = walk(v)
                if r:
                    return r
        elif isinstance(node, list):
            for item in node:
                r = walk(item)
                if r:
                    return r
        return None
    return walk(receipt)


def _norm_host(host: Optional[str]) -> Optional[str]:
    """One spelling per host, so a comparison is between hosts not strings.

    Every identity comparison in this package is `==` between two of these,
    and both sides can be written by whoever wrote the receipt. A hostname is
    case insensitive by definition and may carry a trailing dot for the root
    label, so platform.example, Platform.Example and platform.example. are
    one host written three ways. Comparing them raw meant a single capital
    letter separated a witness from the subject it was signing for, and the
    level went from W1 to W3 on that.

    Normalising here rather than at each comparison, because there are
    several and the next one added would have inherited the same hole.
    """
    if not host:
        return host
    h = host.strip().lower()
    if h.endswith(".") and not h.endswith(":."):
        h = h[:-1]
    return h or None


def controller_of(anchor_url: str) -> Optional[str]:
    """
    Derive the controlling identity of an anchor from where it was served.

    https://x.example.com/.well-known/jwks.json  ->  x.example.com
    did:web:example.com:keys:1                   ->  example.com
    file:./anchors/foo.json                      ->  local:foo.json  (test only)

    The result is normalised. See _norm_host: these strings are compared with
    == to decide whether a witness is the subject, and an unnormalised host
    made that comparison answerable by choosing a capital letter.
    """
    if anchor_url.startswith("did:web:"):
        rest = anchor_url[len("did:web:"):]
        host = rest.split(":")[0]
        return _norm_host(host.replace("%3A", ":"))
    if anchor_url.startswith(("http://", "https://")):
        return _norm_host(urlparse(anchor_url).netloc or None)
    if anchor_url.startswith("file:"):
        return "local:" + os.path.basename(anchor_url[5:])
    return None


class AnchorStore:
    """
    A local, offline anchor set standing in for live JWKS / DID resolution.

    Each entry records the URL the key would have been served from, so the
    controller derivation is identical to the online path. Test fixtures and
    production resolution therefore produce the same evidence shape.
    """

    def __init__(self, path: str):
        with open(path) as fh:
            self.doc = json.load(fh)
        self.keys: Dict[str, Dict[str, Any]] = {}
        for entry in self.doc.get("anchors", []):
            for k in entry.get("keys", []):
                self.keys[k["kid"]] = {
                    "public_key_hex": k["public_key_hex"],
                    "served_from": entry["served_from"],
                }

    def resolve(self, kid: str) -> Tuple[Optional[str], Optional[str], Fact]:
        """
        Return (public_key_hex, anchor_url, evidence_fact).

        anchor_url is the place the key was actually retrieved from. That value,
        and not any field in the receipt, is what the level is computed from.
        """
        hit = self.keys.get(kid)
        if not hit:
            return None, None, Fact(
                name="E1_anchor_url",
                value=None,
                kind=ABSENT,
                how=f"no anchor in the configured trust set serves kid {kid!r}",
            )
        return hit["public_key_hex"], hit["served_from"], Fact(
            name="E1_anchor_url",
            value=hit["served_from"],
            kind=OBSERVED,
            how=f"key for kid {kid!r} was retrieved from this location by the resolver",
        )
