"""wil: grade the witness independence of an attestation or a set of them."""
import argparse, glob, hashlib, json, os, sys

from .level import grade_set, OperatorGraph, ORDER, WU, W2, W3
from .resolve import AnchorStore

ENGINE_VERSION = "0.1.0"


def corpus_digest(root):
    """
    Name the corpus a result was produced against.

    The ACB charter asks that a published result name the engine version, the
    corpus version and the date. A digest over the vector and anchor files is the
    corpus version, and it changes the moment any fixture does.
    """
    h = hashlib.sha256()
    for pattern in ("vectors/*.json", "anchors/*.json"):
        for path in sorted(glob.glob(os.path.join(root, pattern))):
            with open(path, "rb") as fh:
                h.update(fh.read())
    return h.hexdigest()[:16]


def require_error(level):
    """Why `level` cannot be used as a --require threshold, or None.

    Two rejections.

    An unknown level used to reach ORDER.index and raise ValueError, which
    exits with a traceback rather than a message.

    W2? is rejected for a longer reason. ORDER is a single line from weakest to
    strongest, and every other value on it describes the strength of what was
    shown. W2? describes what was not determined. Mixing the two on one axis
    means a gate can be satisfied by supplying less: the same receipts grade W2
    with an operator graph and W2? without one, and W2? sorts higher, so
    `--require W2?` fails for the party who declared their operator
    relationships and passes for the party who did not.

    That is this tool's own argument run backwards. Silence is not evidence of
    independence, and a threshold that rewards it is not a threshold. Grading
    still reports W2? exactly as before; it just cannot be demanded, because
    "undetermined" is not a bar anything clears.
    """
    if level not in ORDER:
        return ("--require %s is not a level. Levels are: %s"
                % (level, ", ".join(ORDER)))
    if level == WU:
        return (
            "--require %s is not a threshold.\n"
            "  %s means the anchor is not the subject's and nothing has\n"
            "  established that it is independent. It records what was not\n"
            "  determined, not how much was shown, so it sits on ORDER above\n"
            "  %s while being a weaker claim than %s.\n"
            "\n"
            "  Requiring it is satisfiable by withholding evidence: the same\n"
            "  receipts grade %s with an operator graph and %s without one.\n"
            "  Require %s or %s instead, depending on which you mean."
            % (WU, WU, W2, W2, W2, WU, W2, W3))
    return None


def main(argv=None):
    ap = argparse.ArgumentParser(prog="wil", description=__doc__)
    ap.add_argument("input", help="a vector file, or a JSON file holding one receipt "
                                  "or a list of receipts")
    ap.add_argument("--trust-set", required=True,
                    help="anchor set: which locations serve which kid")
    ap.add_argument("--operator-graph", default=None,
                    help="operator-declared relationships; every fact in it is marked "
                         "operator_declared in the output")
    ap.add_argument("--json", action="store_true", help="machine readable output")
    ap.add_argument("--observed-at", default=None,
                    help="ISO timestamp naming when this result was produced; supplied "
                         "rather than read from the clock so a result is reproducible")
    ap.add_argument("--require", default=None,
                    help="minimum level to accept, e.g. W3; exit 1 if not reached")
    args = ap.parse_args(argv)

    with open(args.input) as fh:
        doc = json.load(fh)
    if isinstance(doc, dict) and "attestations" in doc:
        receipts, expect = doc["attestations"], doc.get("expect")
    elif isinstance(doc, list):
        receipts, expect = doc, None
    else:
        receipts, expect = [doc], None

    store = AnchorStore(args.trust_set)
    graph = OperatorGraph(json.load(open(args.operator_graph))
                          if args.operator_graph else None)

    result = grade_set(receipts, store, graph)
    root = os.path.dirname(os.path.dirname(os.path.abspath(args.input))) \
        if os.path.basename(os.path.dirname(os.path.abspath(args.input))) in ("vectors",) \
        else os.path.dirname(os.path.abspath(args.input))
    result["corpus"] = os.path.basename(args.input)
    result["corpus_version"] = corpus_digest(root)
    result["engine"] = "wil"
    result["engine_version"] = ENGINE_VERSION
    result["observed_at"] = args.observed_at
    if expect:
        result["expected"] = expect
        result["match"] = (result["set_level"] == expect)

    if args.json:
        print(json.dumps(result, indent=2))
    else:
        print(f"{result['set_level']}  {result['set_label']}   ({result['corpus']})")
        print(f"   engine wil {ENGINE_VERSION}   corpus {result['corpus_version']}"
              + (f"   observed {result['observed_at']}" if result["observed_at"] else ""))
        for a in result["attestations"]:
            print(f"   {a['level']}  kid={a['kid']}  anchor={a['anchor_controller']}")
            print(f"        {a['reason']}")
        for c in result["set_checks"]:
            print(f"   [{c['id']}] {c['outcome']}")
        if result["contains_declared_input"]:
            print("   note: this result rests on at least one operator-declared input")

    if args.require:
        err = require_error(args.require)
        if err:
            print(err, file=sys.stderr)
            return 2
        if ORDER.index(result["set_level"]) < ORDER.index(args.require):
            print(f"required {args.require}, measured {result['set_level']}",
                  file=sys.stderr)
            return 1
    if expect and not result["match"]:
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
