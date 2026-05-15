// SPDX-License-Identifier: MIT

export * as base64url from "./base64url";
export { PkAuthHttpError } from "./http";
export {
  PkAuthCeremonyClient,
  decodeCreationOptions,
  decodeRequestOptions,
  encodeAuthenticationResponse,
  encodeRegistrationResponse,
} from "./ceremonies";
export type {
  CeremonyOptions,
  FinishRegistrationParams,
  StartAuthenticationParams,
  StartRegistrationParams,
} from "./ceremonies";
export { PkAuthAdminClient } from "./admin";
export type * from "./types";

import { PkAuthAdminClient } from "./admin";
import { PkAuthCeremonyClient } from "./ceremonies";
import type { CeremonyOptions } from "./ceremonies";
import type { ClientOptions } from "./types";

/** Convenience facade: a single object exposing both ceremony and admin clients. */
export class PkAuthClient {
  readonly ceremonies: PkAuthCeremonyClient;
  readonly admin: PkAuthAdminClient;

  constructor(options: ClientOptions, ceremonyOptions: CeremonyOptions = {}) {
    this.ceremonies = new PkAuthCeremonyClient(options, ceremonyOptions);
    this.admin = new PkAuthAdminClient(options);
  }
}
