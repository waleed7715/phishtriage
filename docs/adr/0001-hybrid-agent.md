# ADR-0001: Hybrid agent: deterministic checks in code, scarce lookups chosen by the model

- Status: Accepted
- Date: 2026-11-01

## Context
Most triage work (parsing, SPF/DKIM/DMARC, lookalike scoring, abuse.ch lookups) is deterministic and cheap.
VirusTotal's public API allows 4 lookups/minute and 500/day, so emails with many links can't be fully checked.

## Decision
Code runs every cheap check on every indicator. The Claude agent decides which indicators deserve scarce
lookups, retrieves similar analyst-confirmed cases, and writes the verdict, which code then validates.

## Alternatives considered
- Single LLM call with all evidence: cheaper and more predictable; kept as an ablation baseline.
- Fully agentic loop calling every tool: higher cost and variance for work code does better.
- LangChain/LangGraph: hides prompts and caching behavior; the manual loop gives exact traces.

## Consequences
Two code paths to test (rules and agent). Agent loop needs hard caps and a rules-only fallback.

## How we'll know
Phase 5 ablation: if single-call matches agent recall/FPR at lower cost, single-call becomes the default.
