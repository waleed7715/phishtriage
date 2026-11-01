# ADR-0002: API + worker + Postgres behind Caddy

- Status: Accepted
- Date: 2026-11-01

## Context
The service parses hostile files and makes slow model calls (seconds to a minute).

## Decision
A FastAPI API that only authenticates, deduplicates and enqueues; a separate worker with no inbound port that
parses and analyzes; Postgres (with pgvector) for jobs, results, intel cache and embeddings; Caddy for TLS.

## Alternatives considered
- One container with SQLite: simpler, but the process facing the network would also parse hostile bytes.
- Adding Redis/Celery: unnecessary below one worker; Postgres SKIP LOCKED queues are enough.

## Consequences
Async API (202 + poll/callback). Four containers to operate. Egress rules apply to the worker only.

## How we'll know
If load tests show the Postgres queue limits throughput, revisit with a dedicated queue.
