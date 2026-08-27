# Contributing

## The one rule

A check must state the evidence it reads, and whether that evidence was observed by the run
or declared by an operator. A check that reads a field out of the artifact it is grading and
treats it as a fact has not measured anything, because the artifact is written by the party
being measured.

## Adding a vector

Vectors live in `vectors/` and are produced by `tools/gen_vectors.py`. Do not hand-edit a
vector file. The generator is the source and CI regenerates the corpus and diffs it against
what is committed, so a hand edit will fail the run.

A new vector needs a reason. Say in its `why` field what an implementation would have to get
wrong for it to fail, and prefer cases where a plausible wrong implementation reaches a
different answer than the right one. `A3-two-dids-one-domain` is the model: an
implementation that counts distinct `kid` values passes every other vector and fails that
one, and `selftest.py` contains the wrong implementation to prove it.

## Adding an adapter

An adapter in `wil/adapters.py` answers three questions about another format and nothing
else: who the artifact is about, where the verification key came from, and what bytes that
format signs. Declare the signing profile rather than letting the verifier guess among
conventions.

An adapter must not compute a level, must not read an independence claim out of the format,
and must not decide where to look for a key based on a field inside the artifact.

## Adding a level

Do not, without a case that the existing levels cannot express. The ladder is deliberately
short and every rung is grounded in something already published elsewhere.

## Falsifiability

`selftest.py` has two halves and a change should usually touch both. The first plants a
failure and requires the suite to notice it. The second plants a distractor and requires the
level not to move. If a change adds a check, add the planted failure that proves the check
is load bearing; if it adds tolerance, add the distractor that proves the tolerance is
bounded.

## Reporting a level

A published level should name the engine version, the corpus version and the observation
time, and should say whether the result rests on an operator-declared input. `--observed-at`
takes the time rather than reading the clock, so a result stays reproducible.

## What this project will not do

It will not rank implementations, publish a leaderboard, or grade anything on honesty,
correctness or quality. It measures the distance between the party signing a record and the
party the record is about. Four corroborating witnesses who are all wrong are four wrong
witnesses, and nothing here says otherwise.
