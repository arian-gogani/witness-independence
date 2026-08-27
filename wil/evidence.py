"""
Evidence primitives for Witness Independence Levels.

The one rule this module exists to enforce: a fact is either OBSERVED by this run
or DECLARED by an operator, and every fact carries which it is. Nothing may be
promoted from declared to observed, and nothing may be read out of a receipt
payload and treated as observed, because a receipt payload is written by the
party being measured.
"""
from dataclasses import dataclass, field
from typing import Optional, List, Dict, Any

OBSERVED = "observed"
DECLARED = "operator_declared"
ABSENT = "absent"


@dataclass
class Fact:
    """A single input to a check, with its provenance."""
    name: str
    value: Any
    kind: str          # OBSERVED | DECLARED | ABSENT
    how: str           # human readable statement of how it was obtained

    def to_dict(self) -> Dict[str, Any]:
        return {"name": self.name, "value": self.value, "kind": self.kind, "how": self.how}


@dataclass
class Check:
    """One rubric line. States the evidence it read, per the W3C ACB charter bullet."""
    id: str
    question: str
    outcome: str
    reads: List[Fact] = field(default_factory=list)

    @property
    def any_declared(self) -> bool:
        return any(f.kind == DECLARED for f in self.reads)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "question": self.question,
            "outcome": self.outcome,
            "reads": [f.to_dict() for f in self.reads],
            "contains_declared_input": self.any_declared,
        }
