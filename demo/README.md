# The demonstration

Two receipts. In both, the `issuer` and the `payload.agent_id` are the same
identifier: the agent is attesting to its own action. Both carry a real Ed25519
signature over RFC 8785 canonical bytes of the envelope minus the signature,
which is the convention the reference vectors use.

The verification key is supplied through an external anchor, satisfying the rule
in `draft-farley-acta-signed-receipts-02`:

> Verifiers MUST NOT accept a verification key transported inside the receipt
> envelope ... unless that key is independently anchored by an authenticated
> trust source.

## Reproducing

    KEY=f7a7693ba10f9439826ba96a11059fdd9931c617ce4f22ea0e0a390e7094c6c9

    npx --yes @veritasacta/verify self-issued.json    --key $KEY
    npx --yes @veritasacta/verify self-issued-t4.json --key $KEY --tier 4
    npx --yes @veritasacta/verify self-issued-t4.json --key $KEY --strict

Measured against `@veritasacta/verify` 0.9.3:

| receipt | verdict | tier | `--tier 4` | `--strict` |
|---|---|---|---|---|
| `self-issued.json` | VALID | T1 basic | exit 2 | exit 0 |
| `self-issued-t4.json` | VALID | T4 privacy | exit 0 | exit 0 |

`self-issued-t4.json` differs from `self-issued.json` only by four fields the
agent wrote about itself: `anchor_uri`, `attestation_mode: "tee"`,
`holder_binding`, and `previousReceiptHash`. Those four fields carry it from T1
to T4, which is the highest tier the verifier currently awards.

The reported features are:

    ed25519-signature, jcs-canonicalization, chain-linkage,
    attestation:tee, anchor-uri, holder-binding

`attestation:tee` is awarded because the payload says `"attestation_mode": "tee"`.
The payload is written by the agent.

## What this does and does not show

It does not show a bug in the verifier. The verifier does exactly what it says:
it detects which verification capabilities a given verification exercised. Every
check it ran, it ran correctly.

It shows that the ladder the ecosystem currently has measures capability, and
that no rung on it asks who held the key relative to the party being described.
An agent that publishes its own JWKS and writes four optional fields reaches the
top of that ladder while attesting to nothing but its own word.

That is the thing `spec/WITNESS-INDEPENDENCE.md` proposes to measure, and it is
orthogonal to the tiers rather than a replacement for them. A receipt can be
T4 and W1 at once, and the two numbers together say something neither says alone.
