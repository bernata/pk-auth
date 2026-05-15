// SPDX-License-Identifier: MIT

import { request } from "./http";
import type {
  AccountSummary,
  BackupCodeBatch,
  BackupCodeCount,
  ClientOptions,
  CredentialSummary,
  EmailDispatchResult,
  EmailVerificationResult,
  PhoneDispatchResult,
  PhoneVerificationResult,
} from "./types";

const PATHS = {
  account: "/auth/admin/account",
  credentials: "/auth/admin/credentials",
  credentialById: (id: string) => `/auth/admin/credentials/${encodeURIComponent(id)}`,
  backupRegen: "/auth/admin/backup-codes/regenerate",
  backupCount: "/auth/admin/backup-codes/count",
  emailStart: "/auth/admin/email/start-verification",
  emailComplete: "/auth/admin/email/complete-verification",
  phoneStart: "/auth/admin/phone/start-verification",
  phoneComplete: "/auth/admin/phone/complete-verification",
} as const;

export class PkAuthAdminClient {
  private readonly client: ClientOptions;

  constructor(client: ClientOptions) {
    if (!client.getToken) {
      throw new Error("pk-auth: admin client requires `getToken` in ClientOptions");
    }
    this.client = client;
  }

  getAccount(): Promise<AccountSummary> {
    return request(this.client, "GET", PATHS.account, undefined, true);
  }

  listCredentials(): Promise<CredentialSummary[]> {
    return request(this.client, "GET", PATHS.credentials, undefined, true);
  }

  renameCredential(credentialId: string, label: string): Promise<CredentialSummary> {
    return request(this.client, "PATCH", PATHS.credentialById(credentialId), { label }, true);
  }

  removeCredential(credentialId: string): Promise<void> {
    return request(this.client, "DELETE", PATHS.credentialById(credentialId), undefined, true);
  }

  regenerateBackupCodes(): Promise<BackupCodeBatch> {
    return request(this.client, "POST", PATHS.backupRegen, "", true);
  }

  remainingBackupCodes(): Promise<BackupCodeCount> {
    return request(this.client, "GET", PATHS.backupCount, undefined, true);
  }

  startEmailVerification(email: string): Promise<EmailDispatchResult> {
    return request(this.client, "POST", PATHS.emailStart, { email }, true);
  }

  completeEmailVerification(token: string): Promise<EmailVerificationResult> {
    return request(this.client, "POST", PATHS.emailComplete, { token }, true);
  }

  startPhoneVerification(phone: string): Promise<PhoneDispatchResult> {
    return request(this.client, "POST", PATHS.phoneStart, { phone }, true);
  }

  completePhoneVerification(phone: string, code: string): Promise<PhoneVerificationResult> {
    return request(this.client, "POST", PATHS.phoneComplete, { phone, code }, true);
  }
}
