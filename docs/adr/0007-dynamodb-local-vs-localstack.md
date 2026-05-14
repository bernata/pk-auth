# 7. DynamoDB Local over LocalStack for integration tests

Date: 2026-05-14

## Status

Accepted.

## Context

The brief (§3) leaves the DynamoDB integration-test backend choice open: "LocalStack for DynamoDB or `amazon/dynamodb-local` — pick whichever is faster on a cold CI run and document the choice in an ADR." pk-auth's persistence module needs a backend it can spin up via Testcontainers, run thousands of small operations against, and tear down cleanly.

Two practical options:

- **`amazon/dynamodb-local`** — Amazon's official local emulator. JAR-based, single-purpose. The Docker image is ~250 MB. Starts in 1–3 seconds. Supports a strict subset of the production API (recent CRUD + GSI + TTL) and matches the wire format exactly. No IAM, no STS, no auto-scaling, no streams.
- **LocalStack** — multi-AWS-service emulator (DynamoDB, S3, SQS, Lambda, …). Docker image is ~1.5 GB. Starts in 5–10 seconds on a warm cache and longer cold. The DynamoDB implementation is itself a wrapper around `dynamodb-local`. Adds value when you need IAM/STS/cross-service flows.

## Decision

Use `amazon/dynamodb-local:latest` via Testcontainers. pk-auth's persistence tests only exercise the DynamoDB control-plane and data-plane operations the production module uses; we never touch IAM, STS, KMS, or any other service. The smaller image, lower cold-start time, and tighter API surface make `dynamodb-local` the better fit.

Concretely, `DynamoDbLocalFixture` starts one container per JVM (Testcontainers reuse enabled), then the `DynamoDbCeremonyIntegrationTest` creates a fresh pair of tables (random suffix) so concurrent test classes don't collide.

## Consequences

- **Positive — faster CI.** ~5–7 seconds saved on every cold persistence-test run versus LocalStack. Local dev iteration is also noticeably snappier.
- **Positive — smaller surface, fewer surprises.** dynamodb-local matches the production API more faithfully than LocalStack's reimplementation.
- **Negative — no IAM / STS / cross-service tests possible from this container.** Phase 5 does not need them; a future module that wires AWS IAM into auth would need a different fixture (LocalStack or real cloud).
- **Negative — no DynamoDB Streams.** pk-auth doesn't use streams; if a future module does, we'll need a different backend or accept the LocalStack startup cost.

## Open follow-ups

- If we ever add Stream-based cache invalidation or KMS-encrypted attributes, the choice gets revisited. Document with a successor ADR.
