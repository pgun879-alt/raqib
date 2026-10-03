# Working on raqib

This is a portfolio project, so it is not looking for feature contributions. This file exists for
a different reason: the README claims another developer could pick this code up, and that claim
should be checkable. If you are evaluating the project, reviewing it, or forking it for your own
use, everything you need is below.

## Setting up

Python 3.11 or newer. `.python-version` pins 3.13, which is what the tests were measured on.

```bash
make setup      # create .venv and install the package with dev extras
make check      # run every gate the CI runs
make demo       # full offline demo: robots, false positives, change, outage, recovery
```

`make help` lists every target. **Nothing in `make setup`, `make check` or `make demo` reaches
outside your machine.** The demo serves a bundled site on `127.0.0.1:8999` and watches that. Start
from `targets.example.yaml` when you write your own `targets.yaml`.

## The gates

`make check` runs the same four things CI runs, and all four must be clean:

| Gate | Command | Standard |
|---|---|---|
| Format | `ruff format --check .` | 100-column lines, no exceptions |
| Lint | `ruff check .` | the rule set in `pyproject.toml`, zero findings |
| Types | `mypy` | `disallow_untyped_defs`, so every function is annotated |
| Tests | `pytest` | 298 passing, zero skipped |

CI additionally runs `scripts/check_repo_hygiene.py`, which fails the build if a database, a
virtual environment or a credential-shaped literal has been committed. Run it locally with
`python scripts/check_repo_hygiene.py` before any commit.

Ruff's rule selection and the few deliberate `ignore` entries are documented inline in
`pyproject.toml`, each with the reason it is there. Please do not add a bare `# noqa` — if a rule
genuinely does not apply, say why in a comment next to it, as the existing suppressions do.

## The parts that need care

This tool's value is that it is a *safe* network client. Three modules carry that, and a careless
change to any of them turns it into the thing it was built not to be.

**`netguard.py` — the SSRF guard.** Every hostname is resolved, **every** returned address is
classified, and the connection is then **pinned** to the approved address with an explicit `Host`
header. The pinning is not decoration: without it the HTTP client resolves again independently,
which reopens a DNS-rebinding window. For the same reason `follow_redirects=True` is never used —
redirects are followed manually so each hop re-enters validation. If you add a code path that
fetches a URL, it goes through this module; there is no second way in.

**`robots.py` — the enforcement.** It takes text and performs no network I/O of its own, which is
deliberate: the stdlib `urllib.robotparser` fetches with no timeout, no custom agent and no address
validation, and ignores `Crawl-delay`. Longest-match precedence with `Allow` winning ties, plus `*`
and `$`, is what the tests pin down. If `robots.txt` cannot be read, the fetch **fails closed** —
and an outage must be reported as an outage, not as a robots refusal, which is a bug this code has
already had once.

**`alerting.py` — the de-duplication.** Alerts fire on *state change*, keyed on a fingerprint of the
current state. A monitor that alerts every poll is a monitor people mute. Recovery detection reads
the previous check, and getting that index wrong once meant recovery alerts never fired at all.

Changes to the `security_scan` module must stay **passive**: TLS metadata, headers, cookie flags,
mixed content. No probing, no fuzzing, no exploitation. The `authorised: true` gate stays in front
of it.

## Tests

A behaviour change needs a test that fails before it and passes after. The suite is offline and
deterministic; if you need a clock or an HTTP response, inject it rather than patching globals.

## Commits

[Conventional Commits](https://www.conventionalcommits.org/), as in the existing history:
`feat(netguard): …`, `fix(robots): …`, `docs: …`. The body should explain *why*, since the diff
already shows *what*.

Do not commit a `.env`, a `targets.yaml`, a database, or anything under `data/` or `reports/`. See
[SECURITY.md](SECURITY.md) for how to report a vulnerability.
