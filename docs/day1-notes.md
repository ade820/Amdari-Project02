# Day 1 Notes

## Build pin: Werkzeug 2.2.2

The baseline `requirements.txt` files pin Flask 2.2.2 but do not pin
Werkzeug. On a fresh build, pip resolves Werkzeug to 3.x, which removed
`url_quote` — Flask 2.2.2 imports that symbol on startup, so all three
services crashed with `ImportError`.

Fix: added `Werkzeug==2.2.2` to all three service `requirements.txt` files.

**Scope note:** This is a build dependency pin, not an application-layer
remediation. None of the AV-*, TV-*, FV-* findings depend on the Werkzeug
version. The fix only makes the baseline runnable so the rest of the
detection pipeline can do its job. The vulnerability index (AV-01 through
FV-07) is unchanged.

Future Day 3 / Day 4 consideration: SCA tooling (Trivy / Dependabot)
should flag the lack of an explicit Werkzeug pin as a supply-chain
fragility risk. This is a small case study in why pinning matters.
