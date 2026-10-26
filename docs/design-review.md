# Security-focused design review

This review records the main design decisions, the security reasoning behind each one, and what a reviewer should question. It accompanies the [threat model](threat-model.md).

## Architecture choices

| Decision | Security reasoning | Reviewer questions |
|---|---|---|
| **Server-rendered HTML with HTMX**, not a separate single-page app plus an API | One origin and one authentication mechanism (session cookie and CSRF token). There are no bearer tokens to store in the browser, and no CORS policy to get wrong. A strict CSP is easy, because the only JavaScript is htmx and a 10-line helper, both served from the app | Does any page need richer interaction that would justify a SPA? |
| **Authorisation in route dependencies** (`Analyst`, `Admin` type aliases) | Each write route declares its minimum role in its signature, so a missing check is visible in review. Hiding buttons in templates is cosmetic only | Is there any write route without a role dependency? `tests/test_web.py` checks the important ones |
| **Derived values are never stored** | Scores, ratings, overdue flags and verification states are computed on every request, so they can't drift from the data or be edited directly | Performance at scale (see the threat model, D2) |
| **Claimed vs. demonstrated control status** are kept in separate fields | This stops the dashboard implying that a control works just because someone said it was implemented | Is 365 days the right validity period? It's set in one constant: `ASSESSMENT_VALID_DAYS` |
| **SQLite** | One file, no network-exposed database, and it suits a single-instance demo | A multi-user production deployment should move to PostgreSQL. The SQLAlchemy models are portable |
| **Fail closed on configuration** | The app refuses to start outside development with the default secret key | Should demo mode also be off by default in production? Today it's on, because the public demo needs it |

## Input handling

- Every form is parsed with a Pydantic model (`app/schemas.py`) that sets types, ranges, lengths, patterns and enums. Unknown fields are ignored.
- Control IDs are validated against the catalog, so a finding can't reference a control that doesn't exist.
- Business rules that span fields, such as "a result needs a date" or "accepting a risk needs a note", are enforced on the server and covered by tests.
- Output is escaped by Jinja2 autoescaping. Nothing is marked `|safe`.

## Secrets and configuration

- All configuration comes from `SECURESCOPE_*` environment variables, with defaults documented in `.env.example`.
- The repository contains no secrets. `.env` is git-ignored.
- The demo password is configuration, not code, and it only applies to seeded demo accounts.

## Dependencies

- Runtime versions are pinned in `requirements.txt`, and CI runs `pip-audit` against them.
- Bandit runs on every push. The only suppressed rule is `B311` (use of `random`), which applies only to generating synthetic seed data.
- htmx is vendored as a static file at a pinned version, so pages never load a script from a CDN.

## What this review doesn't claim

Passing these checks shows that the listed risks were considered and mitigated in code. It isn't a penetration test, and it doesn't certify SecureScope as secure. It also says nothing about the compliance of any organisation that uses a tool like this.
