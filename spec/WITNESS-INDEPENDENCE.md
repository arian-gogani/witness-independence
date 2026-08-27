# Witness Independence Levels (WIL) v0.1

A measurement of how independent an attestation's signer is from the party the
attestation is about.

Status: draft for discussion. Nothing here is adopted by any body.

## 1. The gap this measures

Signed receipts for AI agent actions are converging on a common shape: an Ed25519
signature over RFC 8785 canonical bytes, a `kid` that resolves to a public key, and a
hash chain linking receipts in sequence. Four things are true about that shape as it
currently stands.

**One. The specification requires the key to be anchored, but not to be independent.**
`draft-farley-acta-signed-receipts-02` states:

> Verifiers MUST NOT accept a verification key transported inside the receipt envelope
> (including but not limited to fields such as public_key, verification_key,
> verification_jwk, or any equivalent name under the signed payload) unless that key is
> independently anchored by an authenticated trust source.

That closes one hole. It does not close the adjacent one. The draft contains no normative
text on whether the issuer may be the same party as the agent whose action is recorded. An
agent that publishes its own JWKS at its own well-known endpoint satisfies the rule above
in full while attesting to its own behavior.

**Two. The reference verifier's conformance tiers measure capability, not custody.**
`@veritasacta/verify` 0.9.3 detects tiers T1 through T5 in `src/conformance.js`. T1 is
signature plus canonicalization plus chain linkage; T2 adds selective disclosure; T3 adds
an attestation mode or the presence of an `anchor_uri`; T4 adds VOPRF or holder binding.
Every one of those is reachable by a signer attesting to itself. Nothing in the tier
computation compares the issuer to the subject.

**Three. The shared conformance suite does not test it.** In
`ScopeBlind/agent-governance-testvectors` at `a320f24`, `issuer_id` appears in
`expected/receipt-schema.json` as an optional property and is populated in no fixture. No
check in `conformance/verify.sh` compares an issuer to a subject.

**Four. The vocabulary registry built to canonicalize this ecosystem has no term for it.**
`aeoess/agent-governance-vocabulary` defines three cryptographic attributes:
`signature_capability`, `canonicalization_profile`, `hash_family`. All three describe
algorithm. None describes custody. Its own crosswalk for a third system observes, of that
system's `origin.kind` enum, that "No vocabulary term asks that question."

## 2. Prior art this borrows from, rather than inventing

This is not a new idea. It is an old idea that two mature ecosystems already settled and
that the agent ecosystem has not yet imported.

**SLSA build levels** grade software provenance on exactly this axis. Build L1 is
"Provenance exists describing how the artifact was built" and is characterised as "trivial
to bypass or forge." Build L2 requires that the "build platform runs on dedicated
infrastructure, not an individual's workstation, and the provenance is tied to that
infrastructure through a digital signature." Build L3 requires that the platform prevent
"secret material used to sign the provenance from being accessible to the user-defined
build steps." The progression L1 to L3 is a progression in who holds the key relative to
the thing being described.

**Certificate Transparency** settled the same question for certificate authorities. RFC
9162's architecture rests on the observation that "The logs do not themselves prevent
misissuance, but they ensure that interested parties can detect such misissuance," and
assigns detection to monitors and auditors, roles that by construction cannot be performed
by the CA about itself.

**in-toto** separates the statement from the party that signs it: a Statement names its
`subject` by digest and its `predicateType`, and the envelope carries the signature of a
functionary that is a distinct role from the artifact.

WIL is the same distinction, expressed for agent receipts.

## 3. The levels

Each level names the evidence a checker reads. A level is never taken from a field inside
the receipt, because any field inside the receipt is written by the signer.

| Level | Name | Condition |
|---|---|---|
| W0 | unattested | No signature, or the verification key resolves only from inside the envelope. |
| W1 | self-anchored | The key resolves from an anchor whose controller is the subject. |
| W2 | operator-anchored | The key resolves from an anchor whose controller operates the subject. |
| W3 | independently anchored | The key resolves from an anchor whose controller neither is nor operates the subject. |
| W4 | corroborated | Two or more W3 attestations over the same action whose anchors do not share a controller. |

**W1 is the honest description of most of this field today,** and it is not a defect to
report at W1. It is a defect to report at W1 while presenting the receipt as evidence that
the action occurred. A W1 receipt is evidence that the signer asserted the action occurred.
Those are different claims and the distance between them is the whole subject of this
document.

## 4. What a checker can and cannot observe

This is the part that decides whether the measurement is worth anything.

**Observable, and the checker MUST derive the level only from these:**

- `E1` The URL or DID from which the verification key was actually retrieved. Not the
  `anchor_uri` the receipt claims. The one the resolver fetched.
- `E2` The controller of that anchor: the DNS domain serving the JWKS, or the DID
  controller field of the resolved DID document.
- `E3` The subject identifier the receipt names, used only as the value to compare
  against, never as a source of conclusions.
- `E4` Across two or more attestations: whether their anchors resolve to the same
  controller, computed as a transitive closure rather than a string comparison, because
  two distinct DIDs served from one domain are one witness.

**Not observable by any run, and therefore operator-declared:**

- `D1` Whether an anchor's controller *operates* the subject. Operation is a fact about
  the world. No fetch establishes it. It is the W2/W3 boundary and it must be supplied.

A checker that silently guesses `D1` produces a number that looks measured and is not.
Every WIL result therefore carries, per check, whether its inputs were observed or
declared, and a result containing any declared input is labelled as such in its output.
This mirrors the same correction made elsewhere: the one field of a subject tuple that no
part of a run can observe must be marked operator-declared rather than asserted by the
runner.

## 5. The adversarial cases the vectors must contain

A suite that only contains receipts that should pass measures nothing. These are the cases
an implementation must fail, and the reason each one exists.

- **A1 embedded key.** Key present only inside the envelope. Must be W0 regardless of how
  well formed the rest is. Already normatively required by the draft; included so the
  boundary is tested rather than assumed.
- **A2 self-anchored with a convincing anchor.** A well formed JWKS at a well known path,
  correct `kid`, valid signature, and the domain serving it is the subject's own. Must be
  W1. This is the case that currently passes every published check in the ecosystem.
- **A3 two DIDs, one domain.** Two attestations, two distinct `kid` values, two distinct
  DIDs, both resolving to anchors served by one controller. Must not reach W4. An
  implementation that counts distinct `kid` values reaches W4 here and is wrong.
- **A4 declared independence.** A receipt carrying a field that asserts its own
  independence. Must be ignored entirely. The level must be unchanged by its presence.
- **A5 anchor claimed but not fetched.** `anchor_uri` present and pointing at an
  independent domain, but the key was in fact resolved from elsewhere. Must be graded on
  where the key came from, not on what the receipt says.
- **A6 chained self-attestation.** A valid chain of self-anchored receipts of any length.
  Chain length must not raise the level. Volume of self-attestation is still
  self-attestation.

## 6. Crosswalk

Each row states what the reference requires and, where relevant, that it is silent on
custody. The silences are part of the argument rather than an omission from the table.

| Reference | What it says | Relationship to this measurement |
|---|---|---|
| NIST AI RMF, MEASURE 1.3 | "Internal experts who did not serve as front-line developers for the system and/or independent assessors are involved in regular assessments and updates." | Direct. This is the same distinction, stated for assessment rather than for signing. |
| NIST AI RMF, MEASURE 2.8 | "Risks associated with transparency and accountability ... are examined and documented." | Adjacent. Requires the risk to be documented, not the assessor to be independent. |
| SLSA v1.0, Build L1 to L3 | L1 provenance is "trivial to bypass or forge"; L2 requires signing by dedicated infrastructure; L3 requires signing material to be inaccessible to user-defined build steps. | Direct structural analogue. W1 to W3 is the same progression for agent actions. |
| RFC 9162 | Assigns detection to monitors and auditors; "The logs do not themselves prevent misissuance, but they ensure that interested parties can detect such misissuance." | Direct. These are roles a subject cannot fill about itself. |
| in-toto Statement v1 | Names a `subject` by digest and carries the signature of a functionary in the envelope. | Structural separation of the thing described from the party signing. |
| OWASP Agentic Skills Top 10, AST09 | The receipt over the action reference. | This grades who signs that receipt. |
| EU AI Act, Article 12 | "High-risk AI systems shall technically allow for the automatic recording of events (logs) over the lifetime of the system." | Requires the record to exist. Assigns no custodial responsibility and says nothing about who signs it. |
| EU AI Act, Article 17 | Requires "systems and procedures for record-keeping of all relevant documentation and information" within the quality management system. | Requires the procedure. Contains no independence requirement for the party carrying it out. |
| ISO/IEC 42001:2023 | An AI management system standard on a Plan-Do-Check-Act structure. | No clause is cited here. The standard is not publicly readable, and a clause number nobody in this document has read is not a citation.

## 7. What this does not claim

WIL does not measure whether an action was correct, whether a policy was well written,
whether a signer is honest, or whether an agent is trustworthy. A W4 result from four
corroborating witnesses who are all wrong is four wrong witnesses.

It measures one thing: the distance between the party making the record and the party the
record is about. That distance is currently unmeasured, and every stronger claim in this
field is built on top of it.
