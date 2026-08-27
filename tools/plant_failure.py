"""
Plant a vector whose expected level is wrong, so CI can assert that the suite
notices. Used only by the workflow step named "the suite can actually fail".

This exists because a conformance run that prints a failure and returns 0 has
reported nothing, and that is a live defect in at least one published suite.
The gate has to be tested like any other code path.
"""
import json
import os

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)

src = os.path.join(ROOT, "vectors", "A2-self-anchored.json")
dst = os.path.join(ROOT, "vectors", "_planted.json")

doc = json.load(open(src))
doc["expect"] = "W4"
doc["why"] = ("Planted by tools/plant_failure.py. A2 is self-anchored and grades W1; "
              "claiming W4 here must make run.sh return non-zero.")
json.dump(doc, open(dst, "w"), indent=2)
print("planted", os.path.relpath(dst, ROOT), "expecting W4 on a W1 vector")
