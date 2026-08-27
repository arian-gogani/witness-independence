# Witness Independence Levels

A measurement of the distance between the party that signs a record and the party
the record is about.

Signed receipts for AI agent actions are converging on a common shape. The shape
is good. What nothing currently measures is who held the signing key relative to
the agent whose action was recorded, and the answer to that question changes what
a receipt is evidence of.

- `spec/WITNESS-INDEPENDENCE.md` is the proposal, with the prior art it borrows
  from and the gap it addresses.
- `demo/` demonstrates the gap: a receipt an agent wrote about itself reaches the
  highest conformance tier the reference verifier awards.
- `vectors/` are the conformance vectors, most of them adversarial.
- `wil/` is the reference implementation.
- `selftest.py` plants failures and requires the suite to notice them.

## Running

    pip install pynacl
    ./run.sh          # grade every vector against its expected level
    python3 selftest.py   # plant failures and confirm the suite is load bearing

`run.sh` returns its verdict. A suite that prints a failure and exits 0 has not
reported anything, and that is a live defect in at least one published suite, so
the exit path here has an explicit test.

## The levels

| Level | Name | Condition |
|---|---|---|
| W0 | unattested | no signature, or the key resolves only from inside the envelope |
| W1 | self-anchored | the key resolves from an anchor the subject controls |
| W2 | operator-anchored | the anchor's controller is declared to operate the subject |
| W2? | undetermined | the anchor is not the subject's, and nothing states whether its controller operates the subject |
| W3 | independently anchored | the controller is declared to have no operational relationship to the subject |
| W4 | corroborated | two or more W3 attestations resting on roots that do not converge |

W2? exists because of a defect found in this tool during its own falsifiability
pass. In the first implementation, omitting the operator graph promoted every
non-self-anchored attestation to W3: a missing input produced the stronger
verdict. Independence is now something a party has to state, because a graph that
stays silent about a controller has not shown that controller to be independent.
The regression test is `no input combination lets silence reach W3 or above`.

## Format adapters

`wil/adapters.py` holds adapters that express another format in the evidence shape this tool
reads. An adapter answers three questions and nothing else: who the artifact is about, where
the verification key came from, and whether the signature holds over the bytes that format
actually signs. It never invents a level and never reads an independence claim.

The AIVS adapter implements `draft-stone-aivs-00`. Run it:

    python3 tools/make_aivs_bundle.py out/aivs_proof_demo.tar.gz
    python3 tools/grade_aivs.py out/aivs_proof_demo.tar.gz out/aivs-external-anchor.json

A bundle built exactly to that spec, with every member present, the chain hash recomputing
and agreeing across all three places it is written, and a valid Ed25519 signature, grades
**W0**. Not because anything is broken. Section 8.1 of that draft claims integrity,
completeness and ordering, and all three hold here; WIL does not grade them. Section 8.2
says "The public key in the bundle is self-asserted," and W0 is that sentence expressed as
a level.

Publishing the identical key at a well-known endpoint instead of carrying it inside the
archive moves the same bundle, byte for byte unchanged, to **W2?**. The distance between W0
and the rest of the ladder is a publishing step, not a format change.

Adapters declare what their format signs. A verifier that guesses among signing conventions
until one succeeds is a verifier that can be steered, so guessing is the fallback for
unlabelled input rather than the default, and there is a test named `a declared signing
profile is not silently replaced by a guess`.

## What it grades today

| artifact | level |
|---|---|
| the three `aps-gateway-enforcement` reference receipts in `ScopeBlind/agent-governance-testvectors` | W2? |
| a Nobulex receipt built as its published crosswalk describes | W1 |

Both readings are unflattering in the sense that neither reaches W3, and neither
is an accusation. A W1 receipt is a valid, well formed, cryptographically sound
record of what its signer asserted. The level says how far that is from a record
of what happened.

## Where this came from, and where it is being discussed

The measurement exists because four separate places in this ecosystem are silent on the
same question.

-  requires a verification key to be externally
  anchored and never requires the anchor to be independent of the subject. No normative
  text in the draft addresses whether an agent may issue receipts about itself.
-  0.9.3 detects conformance tiers T1 to T5 in 
  from signature, canonicalization, chain linkage, disclosure, attestation mode, anchor
  URI, VOPRF and holder binding. Nothing in that computation compares issuer to subject.
- In  at , the string 
  appears exactly once in the whole repository, as an optional property in
  . It is populated in no fixture, and no check compares an
  issuer to a subject.
-  defines three cryptographic system attributes,
  ,  and . All three describe
  the signature. None describes the signer. The string  appears zero times across
   and all 35 crosswalk files.

Open discussions:

- , on a validator that silently skips 13 of 35
  crosswalks. The single out-of-enum value hiding in that gap belongs to this author.
- , proposing a fourth system attribute for key
  custody.
- , on a suite in which no receipt passes both
  checks while CI reports green.

## What this is not

Not a measure of whether an action was correct, whether a policy was well
written, whether a signer is honest, or whether an agent should be trusted. Four
corroborating witnesses who are all wrong are four wrong witnesses.
