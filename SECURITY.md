# Security policy

## Status of this project

`raqib` is an open-source portfolio project. It has **no production deployment, no users and no
clients**, and it is maintained by one person in his spare time. Only the `main` branch is
supported; there are no releases and no backports.

This project is a network client whose whole job is to be careful, so it is held to a higher bar
than the rest of the portfolio: it resolves and classifies addresses before connecting, enforces
`robots.txt`, and gates its assessment features behind an explicit attestation. A flaw in any of
those is worth reporting, and will be fixed and described honestly in the README rather than
quietly patched.

## Reporting a vulnerability

Use GitHub's **private vulnerability reporting** on this repository: the **Security** tab →
*Report a vulnerability*. That keeps the report private until a fix exists, and needs no email
address from either of us.

For anything that is not sensitive — a hardening suggestion, a question about the threat model, a
documentation error — open a normal issue instead.

Please include the version (commit SHA), the configuration involved, and the smallest target
definition that shows the problem. A failing test is the most useful form a report can take.

**Expect best-effort, unpaid handling.** There is no SLA and no bug bounty. I will acknowledge a
report when I see it, and tell you plainly if I do not intend to fix something.

## In scope

The three design decisions this tool stands on are described in the README. Anything that breaks
one of them is a genuine finding:

- **Any bypass of the SSRF guard** — this is the highest-value report. Concretely: an address
  class that `netguard` fails to classify as internal; an encoding, IPv6 form or IPv4-mapped /
  6to4 representation that smuggles a private address past it; a DNS-rebinding window between the
  classification and the connection, despite the connection being pinned to the approved address;
  or a redirect hop that reaches a host without being re-validated.
- **Fetching a path that `robots.txt` disallows** — a precedence error in longest-match, an
  `Allow`/`Disallow` tie resolved the wrong way, a mishandled `*` or `$`, or any path where an
  unreadable `robots.txt` stops failing closed.
- **Performing a `security_check` against a target whose `authorised` flag is false**, or any way
  to reach the assessment code without that attestation.
- **Escaping the politeness gate** — ignoring the per-host gap or a site's stricter `Crawl-delay`,
  turning this tool into something that hammers a host.
- **XSS or template injection in the generated HTML report**, which renders attacker-controlled
  page content and is autoescaped for exactly that reason.
- **Deserialisation or injection through `targets.yaml`** — the loader uses `yaml.safe_load`
  specifically so a targets file cannot construct arbitrary Python objects.
- **Exceeding `max_response_bytes`**, or any unbounded read that lets a hostile server exhaust
  memory.
- **Secret disclosure** — a webhook URL or Telegram token appearing in a report, a log line or an
  alert payload where it does not belong.

## Deliberate decisions that are not vulnerabilities

Please read these before reporting, so neither of us wastes an afternoon:

- **`allow_private_targets` disables part of the SSRF protection on purpose.** It defaults to
  `false`, exists so you can watch a local test server, and the CLI warns on every run while it is
  on. "Setting it to true allows loopback" is the documented behaviour of the flag, not a bypass.
- **`respect_robots` can be turned off on purpose.** It defaults to `true`, and the README restricts
  the opt-out to sites you own. Disabling it yourself is not a vulnerability in this tool.
- **`authorised: true` is an attestation, not an authorisation check.** This tool cannot verify that
  you own a site; it can only refuse to assess one until you have said you do, and make that claim
  explicit and auditable in your own config. Pointing out that a user can lie to themselves here is
  not a finding.
- **The assessment is passive.** It reads TLS metadata, response headers, cookie flags and mixed
  content. There is no probing, no fuzzing and no exploitation, and that is deliberate — requests
  to add active scanning will be declined.
- **The default user agent identifies the tool, not its operator.** Replacing it with contact
  details that reach *you* is an operator responsibility, documented in `.env.example`.
- **Everything in `.env.example` is a placeholder.** A credential-shaped string there is not a
  leaked credential.
- **`demo_site/private/secret.html` contains no secret.** It is a fixture that must *not* be
  fetched, used to prove `robots.txt` compliance. Its contents say exactly that.

## What is not covered

Issues in Python, `httpx`, `jinja2` or `PyYAML` themselves — report those upstream. Vulnerabilities
that require an attacker to already control the host, the SQLite file or the environment variables
are out of scope, since every secret this project has lives there.

Finally: this tool is for watching sites **you own or have permission to watch**. Reports that
amount to "it can be pointed at a third party" describe the purpose of a monitor, and the
authorisation boundary in the README is where that line is drawn.
