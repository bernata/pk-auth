// SPDX-License-Identifier: MIT

/**
 * Discriminated union mirroring the Java sealed result hierarchies
 * (AuthenticationResult / RegistrationResult) as returned by the pk-auth HTTP adapters.
 *
 * Authentication outcomes: success | challenge_invalid | origin_mismatch |
 *   signature_invalid | unknown_credential | failed
 *
 * Registration outcomes: success | challenge_invalid | origin_mismatch |
 *   attestation_rejected | duplicate_credential | invalid_payload | failed
 */
export type CeremonyResult =
  | { outcome: 'success'; token: string; credentialId?: string }
  | { outcome: 'challenge_invalid'; detail?: string }
  | { outcome: 'origin_mismatch'; detail?: string }
  | { outcome: 'signature_invalid'; detail?: string }
  | { outcome: 'unknown_credential'; detail?: string }
  | { outcome: 'attestation_rejected'; detail?: string }
  | { outcome: 'duplicate_credential'; detail?: string }
  | { outcome: 'invalid_payload'; detail?: string }
  | { outcome: 'failed'; detail?: string };

/** Type guard: narrows a CeremonyResult to the success variant. */
export function isCeremonySuccess(
  result: CeremonyResult,
): result is { outcome: 'success'; token: string; credentialId?: string } {
  return result.outcome === 'success';
}

/** Type guard: narrows a CeremonyResult to any failure variant. */
export function isCeremonyFailure(
  result: CeremonyResult,
): result is Exclude<CeremonyResult, { outcome: 'success' }> {
  return result.outcome !== 'success';
}
