"""
Live key resolution: HTTPS JWKS and did:web.

Offline anchor sets are how the vectors run without a network. This is how the
same measurement runs against real endpoints. Both produce the same evidence
shape, and the level is computed from the same field either way: the location
the key was actually retrieved from.

Two rules this module exists to keep:

  1. The location recorded is the location that answered, after redirects. A
     redirect from an independent host to the subject's own host changes who
     controls the anchor, and recording the requested URL rather than the final
     one would hide exactly that.

  2. Nothing is read from the artifact to decide where to look. The caller
     supplies the anchor location. A receipt that names its own anchor_uri is
     naming a place it would like to be checked against.
"""
import base64
import json
import ssl
import urllib.request
import urllib.error
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import urlparse, quote

USER_AGENT = "wil/0.1.0 (witness independence levels)"
TIMEOUT = 15


class Resolution:
    def __init__(self, kid, key_hex, requested_url, final_url, chain, error=None):
        self.kid = kid
        self.key_hex = key_hex
        self.requested_url = requested_url
        self.final_url = final_url
        self.redirect_chain = chain
        self.error = error

    @property
    def redirected(self) -> bool:
        return bool(self.final_url and self.final_url != self.requested_url)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "kid": self.kid, "key_hex": self.key_hex,
            "requested_url": self.requested_url, "final_url": self.final_url,
            "redirect_chain": self.redirect_chain, "redirected": self.redirected,
            "error": self.error,
        }


def _fetch_json(url: str) -> Tuple[Optional[Any], str, List[str], Optional[str]]:
    """Fetch JSON, returning (doc, final_url, redirect_chain, error)."""
    chain: List[str] = []

    class _Tracker(urllib.request.HTTPRedirectHandler):
        def redirect_request(self, req, fp, code, msg, headers, newurl):
            chain.append(newurl)
            return super().redirect_request(req, fp, code, msg, headers, newurl)

    ctx = ssl.create_default_context()
    opener = urllib.request.build_opener(_Tracker,
                                         urllib.request.HTTPSHandler(context=ctx))
    req = urllib.request.Request(url, headers={"User-Agent": USER_AGENT,
                                               "Accept": "application/json"})
    try:
        with opener.open(req, timeout=TIMEOUT) as resp:
            final = resp.geturl()
            return json.loads(resp.read().decode()), final, chain, None
    except urllib.error.HTTPError as exc:
        return None, url, chain, f"HTTP {exc.code}"
    except Exception as exc:
        return None, url, chain, str(exc)


def _keys_from_jwks(doc: Any) -> Dict[str, str]:
    """kid -> raw Ed25519 public key hex, from a JWKS document."""
    out: Dict[str, str] = {}
    for k in (doc or {}).get("keys", []):
        if k.get("kty") != "OKP" or k.get("crv") != "Ed25519":
            continue
        x = k.get("x")
        if not x:
            continue
        try:
            raw = base64.urlsafe_b64decode(x + "=" * (-len(x) % 4))
        except Exception:
            continue
        if len(raw) == 32 and k.get("kid"):
            out[k["kid"]] = raw.hex()
    return out


def _keys_from_did_document(doc: Any) -> Dict[str, str]:
    """kid -> key hex, from the verificationMethod entries of a DID document."""
    out: Dict[str, str] = {}
    for vm in (doc or {}).get("verificationMethod", []) or []:
        kid = vm.get("id")
        jwk = vm.get("publicKeyJwk")
        if jwk:
            for k, v in _keys_from_jwks({"keys": [dict(jwk, kid=kid)]}).items():
                out[k] = v
                if isinstance(kid, str) and "#" in kid:
                    out[kid.split("#", 1)[1]] = v
    return out


def did_web_to_url(did: str) -> Optional[str]:
    """did:web:example.com:a:b -> https://example.com/a/b/did.json"""
    if not did.startswith("did:web:"):
        return None
    parts = did[len("did:web:"):].split(":")
    host = parts[0].replace("%3A", ":")
    path = "/".join(quote(p) for p in parts[1:])
    return (f"https://{host}/{path}/did.json" if path
            else f"https://{host}/.well-known/did.json")


def resolve_live(kid: str, anchor: str) -> Resolution:
    """
    Retrieve `kid` from `anchor`, which is an https JWKS URL or a did:web
    identifier. The recorded location is the one that answered.
    """
    url = did_web_to_url(anchor) if anchor.startswith("did:web:") else anchor
    if not url:
        return Resolution(kid, None, anchor, None, [], "anchor is not an https URL or a did:web")
    doc, final, chain, err = _fetch_json(url)
    if err:
        return Resolution(kid, None, url, None, chain, err)
    keys = _keys_from_jwks(doc) or _keys_from_did_document(doc)
    return Resolution(kid, keys.get(kid), url, final, chain,
                      None if kid in keys else f"anchor served no key with kid {kid!r}")


class LiveAnchorStore:
    """
    Same interface as AnchorStore, backed by real fetches.

    `anchors` maps a kid to the location a caller says to look. Nothing here is
    taken from the artifact being graded.
    """

    def __init__(self, anchors: Dict[str, str]):
        self.anchors = anchors
        self.resolutions: Dict[str, Resolution] = {}

    def resolve(self, kid: str):
        from .evidence import Fact, OBSERVED, ABSENT
        where = self.anchors.get(kid)
        if not where:
            return None, None, Fact("E1_anchor_url", None, ABSENT,
                                    f"no anchor location supplied for kid {kid!r}")
        res = resolve_live(kid, where)
        self.resolutions[kid] = res
        if not res.key_hex:
            return None, None, Fact("E1_anchor_url", None, ABSENT,
                                    f"{res.requested_url}: {res.error}")
        how = f"key for kid {kid!r} was retrieved from this location by the resolver"
        if res.redirected:
            how += (f"; the request was made to {res.requested_url} and was redirected, "
                    f"so the recorded location is where it actually answered")
        return res.key_hex, res.final_url, Fact("E1_anchor_url", res.final_url, OBSERVED, how)
