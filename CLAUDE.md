# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project

phishtriage triages phishing `.eml` files using the Claude API. Early stage: only the parser
(`src/phishtriage/parse/`) exists so far; the CLI entry point (`phishtriage:main`) is a stub.
The planned design is recorded in `docs/adr/` (copy `0000-template.md` for new ADRs):

- **ADR-0001 (hybrid agent):** code runs every cheap, deterministic check (parsing, SPF/DKIM/DMARC,
  lookalike scoring, abuse.ch) on every indicator. The Claude agent only picks which indicators get
  scarce VirusTotal lookups (4/min, 500/day), retrieves similar confirmed cases, and writes the
  verdict, which code then validates. The agent loop needs hard caps and a rules-only fallback.
  No LangChain/LangGraph: a manual loop keeps prompts and caching visible. A single-call path is
  kept as an ablation baseline.
- **ADR-0002 (service footprint):** FastAPI API that only authenticates, deduplicates and enqueues;
  a separate worker with no inbound port parses hostile bytes and calls the model; Postgres
  (pgvector, `SKIP LOCKED` queue) and Caddy for TLS. Hostile-input parsing must never move into the
  network-facing process.

## Commands

Python 3.13, managed with `uv`. CI (`.github/workflows/ci.yml`) runs exactly these, so all must pass:

```bash
uv sync --locked                 # fails if uv.lock is stale; run `uv lock` after editing deps
uv run ruff check .
uv run ruff format --check .
uv run mypy                      # strict; covers src, tests and eval
uv run pytest                    # coverage is on by default via addopts
uv run pip-audit --skip-editable
uv run pre-commit run --all-files   # includes gitleaks
```

Single test: `uv run pytest tests/parse/test_headers.py::test_header_text_missing_is_none`
(add `--no-cov` for quieter output). Tests marked `live` call real external APIs and are run
manually only; `--strict-markers` is on, so register any new marker in `pyproject.toml`.

Eval data: `uv run python eval/fetch.py [--dest PATH]` clones the phishing_pot dataset at the commit
pinned in `eval/dataset.toml` into `~/data/phishing_pot` (outside the repo) and writes a SHA-256
manifest next to it. Dataset bytes are kept raw.

## Parser architecture (`src/phishtriage/parse/`)

The parser treats every input as hostile. Pipeline: `intake.load_message` -> `unwrap.unwrap_report`
-> `headers.extract_headers`.

- **`limits.ParseLimits`**: frozen dataclass of resource caps (bytes, MIME depth, parts, defects,
  unwrap layers, header length, addresses, Received hops, etc.), validated as positive ints.
  Every parse function takes `limits: ParseLimits = DEFAULT_LIMITS` and must enforce the relevant
  cap rather than hard-coding numbers.
- **`errors`**: everything raised to callers is a `ParseError` subclass with a stable `reason`
  class var (`input_too_large`, `too_many_parts`, `mime_too_deep`, `not_an_email`). Reason codes are
  a contract; don't rename them. `load_message` wraps any unexpected stdlib exception as
  `ParseError(type(e).__name__)` while re-raising existing `ParseError`s unchanged.
- **`intake.load_message`**: size check before parsing, `BytesParser(policy=policy.default)`,
  requires at least one of From/Date/Subject/Message-ID/Received, then walks MIME iteratively (no
  recursion) counting parts/depth and collecting deduplicated defect class names into `MimeStats`.
- **`unwrap.unwrap_report`**: peels user-reported wrappers (`message/rfc822` parts or `.eml`
  attachments) up to `max_unwrap_layers`, only while exactly one candidate exists at each layer;
  records the reporter's From/Subject from the outer message.
- **`headers`**: header access never raises. `header_text`/`parse_addresses` try the structured
  `policy.default` header first and fall back to `msg.raw_items()` / `email.utils.getaddresses`
  when the structured parse throws. All values go through `normalize_header` (unfold whitespace,
  replace surrogates, truncate). `parse_received` extracts from/by/IP/timestamp from Received
  headers with regexes; IPs are validated with `ipaddress`.

Conventions: results are `@dataclass(frozen=True, slots=True)` with tuples, not lists; dates are
normalized to UTC; addresses are lower-cased.

## Tests

`tests/` mirrors `src/` (`tests/parse/test_<module>.py`). Tests build messages from raw byte header
lines via small local helpers and use Hypothesis property tests for robustness against malformed
input; mypy strict applies to tests too, so annotate them (`-> None`).

## Repo rules

- `*.eml`/`*.msg` and `/data/` are git-ignored; real samples never go in the repo. Only synthetic
  fixtures under `tests/fixtures/**/*.eml` may be committed.
- Secrets live in `.env` (see `.env.example`: `ANTHROPIC_API_KEY`, `ABUSECH_AUTH_KEY`,
  `VIRUSTOTAL_API_KEY`).
- Ruff enables bandit (`S`) rules; a justified suppression gets a `# noqa: S###` with a comment
  explaining why (see `eval/fetch.py`).
- Commit messages use conventional style with scope, e.g. `feat(parse): ...`, `ci: ...`, `docs: ...`.
