// SPDX-License-Identifier: MIT

/**
 * Tests for the CeremonyResult discriminated union and its type guards.
 *
 * Why this file exists:
 *   `src/results.ts` previously had *zero* test coverage. Mutation testing
 *   (StrykerJS) — introduced by Andrew Bernat (@bernata) in PR #39
 *   (https://github.com/codeheadsystems/pk-auth/pull/39) — surfaced this as a
 *   0% mutation-score file: every mutant of `isCeremonySuccess` /
 *   `isCeremonyFailure` survived because no test ever executed them. Line
 *   coverage hid the gap; mutation coverage did not. Thanks to Andrew for
 *   wiring up the tooling that made these blind spots visible.
 *
 * The guards are the public, documented way for callers to narrow a
 * CeremonyResult, so both the positive and the negative branch are pinned
 * here (a guard that always returns the same value is useless, and that is
 * exactly the mutation Stryker injects).
 */

import { describe, expect, it } from "vitest";
import {
  type CeremonyResult,
  isCeremonyFailure,
  isCeremonySuccess,
} from "../src/results";

const success: CeremonyResult = { outcome: "success", token: "jwt", credentialId: "cred-1" };

const failures: CeremonyResult[] = [
  { outcome: "challenge_invalid", detail: "stale" },
  { outcome: "origin_mismatch" },
  { outcome: "signature_invalid" },
  { outcome: "unknown_credential" },
  { outcome: "attestation_rejected" },
  { outcome: "duplicate_credential" },
  { outcome: "invalid_payload" },
  { outcome: "failed", detail: "boom" },
];

describe("CeremonyResult guards", () => {
  it("isCeremonySuccess is true only for the success variant", () => {
    expect(isCeremonySuccess(success)).toBe(true);
    for (const f of failures) {
      expect(isCeremonySuccess(f)).toBe(false);
    }
  });

  it("isCeremonyFailure is true for every non-success variant", () => {
    expect(isCeremonyFailure(success)).toBe(false);
    for (const f of failures) {
      expect(isCeremonyFailure(f)).toBe(true);
    }
  });

  it("the two guards are exact complements", () => {
    for (const r of [success, ...failures]) {
      expect(isCeremonySuccess(r)).toBe(!isCeremonyFailure(r));
    }
  });

  it("narrows to the success payload after isCeremonySuccess", () => {
    const r: CeremonyResult = success;
    if (isCeremonySuccess(r)) {
      // Type narrowing must expose token; assert the runtime value too.
      expect(r.token).toBe("jwt");
      expect(r.credentialId).toBe("cred-1");
    } else {
      throw new Error("expected success to narrow via isCeremonySuccess");
    }
  });
});
