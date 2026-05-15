/**
 * Base64url (RFC 4648 §5) without padding — matches pk-auth's wire format.
 * The server's Jackson module emits unpadded base64url; browsers can mix
 * Uint8Array, ArrayBuffer, or already-base64url strings, so encode handles
 * all three.
 */
type Base64Url = string;
declare function encode(input: ArrayBuffer | Uint8Array | ArrayBufferView): Base64Url;
declare function decode(input: Base64Url): Uint8Array;
declare function decodeToArrayBuffer(input: Base64Url): ArrayBuffer;

type base64url_Base64Url = Base64Url;
declare const base64url_decode: typeof decode;
declare const base64url_decodeToArrayBuffer: typeof decodeToArrayBuffer;
declare const base64url_encode: typeof encode;
declare namespace base64url {
  export { type base64url_Base64Url as Base64Url, base64url_decode as decode, base64url_decodeToArrayBuffer as decodeToArrayBuffer, base64url_encode as encode };
}

/** Caller-supplied bearer-token accessor. Returns null when there's no session yet. */
type TokenAccessor = () => string | null;
/** Construction options shared by the ceremony and admin clients. */
interface ClientOptions {
    /** Base URL for all pk-auth endpoints. Trailing slash is tolerated. */
    apiBase: string;
    /**
     * Returns the current bearer token (null when unauthenticated). Required for admin operations;
     * ceremony operations are anonymous and will not call it.
     */
    getToken?: TokenAccessor;
    /** Override the global fetch (handy for tests). */
    fetch?: typeof fetch;
}
interface RpEntity {
    id: string;
    name: string;
}
interface PublicKeyCredentialUserEntityJson {
    id: Base64Url;
    name: string;
    displayName: string;
}
interface PublicKeyCredentialDescriptorJson {
    id: Base64Url;
    type: "public-key";
    transports?: string[];
}
interface PublicKeyCredentialCreationOptionsJson {
    rp: RpEntity;
    user: PublicKeyCredentialUserEntityJson;
    challenge: Base64Url;
    pubKeyCredParams: {
        type: "public-key";
        alg: number;
    }[];
    timeout?: number;
    excludeCredentials?: PublicKeyCredentialDescriptorJson[];
    authenticatorSelection?: {
        authenticatorAttachment?: "platform" | "cross-platform";
        residentKey?: "discouraged" | "preferred" | "required";
        requireResidentKey?: boolean;
        userVerification?: "discouraged" | "preferred" | "required";
    };
    attestation?: "none" | "indirect" | "direct" | "enterprise";
}
interface PublicKeyCredentialRequestOptionsJson {
    challenge: Base64Url;
    timeout?: number;
    rpId?: string;
    allowCredentials?: PublicKeyCredentialDescriptorJson[];
    userVerification?: "discouraged" | "preferred" | "required";
}
interface StartRegistrationRequest {
    username: string;
    displayName?: string | null;
    label?: string | null;
    challenge?: Base64Url | null;
}
interface StartRegistrationResponse {
    challengeId: string;
    publicKey: PublicKeyCredentialCreationOptionsJson;
}
interface StartAuthenticationRequest {
    username?: string | null;
    challenge?: Base64Url | null;
}
interface StartAuthenticationResponse {
    challengeId: string;
    publicKey: PublicKeyCredentialRequestOptionsJson;
}
interface RegistrationResponseJson {
    id: Base64Url;
    rawId: Base64Url;
    type: "public-key";
    response: {
        clientDataJSON: Base64Url;
        attestationObject: Base64Url;
        transports?: string[];
    };
}
interface AuthenticationResponseJson {
    id: Base64Url;
    rawId: Base64Url;
    type: "public-key";
    response: {
        clientDataJSON: Base64Url;
        authenticatorData: Base64Url;
        signature: Base64Url;
        userHandle: Base64Url | null;
    };
}
interface FinishRegistrationRequest {
    challengeId: string;
    username: string;
    label?: string | null;
    response: RegistrationResponseJson;
}
interface FinishAuthenticationRequest {
    challengeId: string;
    response: AuthenticationResponseJson;
}
/** Server returns the wrapped RegistrationResult; relevant fields are surfaced here. */
interface FinishRegistrationResponse {
    credential: {
        credentialId: Base64Url;
        userHandle: Base64Url;
        label: string;
        transports: string[];
        counter: number;
        backupEligible: boolean;
        backupState: boolean;
        aaguid?: string | null;
        authenticatorData: Base64Url;
    };
}
interface FinishAuthenticationResponse {
    token: string;
}
interface CredentialSummary {
    credentialId: Base64Url;
    label: string;
    createdAt: string;
    lastUsedAt?: string | null;
    counter: number;
    backupEligible: boolean;
    backupState: boolean;
    transports: string[];
}
interface AccountSummary {
    userHandle: Base64Url;
    username: string;
    displayName: string;
    emailVerified: boolean;
    phoneVerified: boolean;
    credentialCount: number;
    backupCodesRemaining: number;
}
interface BackupCodeBatch {
    codes: string[];
}
interface BackupCodeCount {
    remaining: number;
}
interface EmailDispatchResult {
    /** Implementation-defined token / link reference returned by the dispatcher. */
    dispatchId?: string;
    /** Magic-link token (testkit / dev only — real dispatchers send it out of band). */
    token?: string;
}
interface PhoneDispatchResult {
    dispatchId?: string;
    /** OTP code (testkit / dev only — real dispatchers send it via SMS). */
    code?: string;
}
interface EmailVerificationResult {
    email: string;
    verified: boolean;
}
interface PhoneVerificationResult {
    phone: string;
    verified: boolean;
}

declare class PkAuthHttpError extends Error {
    readonly status: number;
    readonly body: string;
    constructor(status: number, body: string);
}

declare const PATHS: {
    readonly startReg: "/auth/passkeys/registration/start";
    readonly finishReg: "/auth/passkeys/registration/finish";
    readonly startAuth: "/auth/passkeys/authentication/start";
    readonly finishAuth: "/auth/passkeys/authentication/finish";
};
interface CeremonyOptions {
    /** Path overrides — useful for the dropwizard adapter, which omits the `/passkeys/` segment. */
    paths?: Partial<typeof PATHS>;
    /** Optional override for navigator.credentials (tests / non-browser callers). */
    credentials?: CredentialsContainer;
}
interface StartRegistrationParams {
    username: string;
    displayName?: string;
    label?: string;
}
interface FinishRegistrationParams extends StartRegistrationResponse {
    username: string;
    label?: string;
}
interface StartAuthenticationParams {
    username?: string;
    /** When true, hands the call to `navigator.credentials.get` with `mediation: "conditional"`. */
    conditional?: boolean;
}
declare class PkAuthCeremonyClient {
    private readonly client;
    private readonly paths;
    private readonly credentials?;
    constructor(client: ClientOptions, options?: CeremonyOptions);
    /**
     * Runs the full registration ceremony: server-start → `navigator.credentials.create` →
     * server-finish. Returns the finish payload (registered credential metadata).
     */
    register(params: StartRegistrationParams): Promise<FinishRegistrationResponse>;
    /**
     * Runs the full sign-in ceremony: server-start → `navigator.credentials.get` →
     * server-finish. Returns the JWT (consumer is responsible for storage).
     */
    authenticate(params?: StartAuthenticationParams): Promise<FinishAuthenticationResponse>;
    startRegistration(body: StartRegistrationRequest): Promise<StartRegistrationResponse>;
    finishRegistration(body: FinishRegistrationRequest): Promise<FinishRegistrationResponse>;
    startAuthentication(body: StartAuthenticationRequest): Promise<StartAuthenticationResponse>;
    finishAuthentication(body: FinishAuthenticationRequest): Promise<FinishAuthenticationResponse>;
    private get credentialsImpl();
    private createCredential;
    private getCredential;
}
declare function decodeCreationOptions(options: PublicKeyCredentialCreationOptionsJson): PublicKeyCredentialCreationOptions;
declare function decodeRequestOptions(options: PublicKeyCredentialRequestOptionsJson): PublicKeyCredentialRequestOptions;
declare function encodeRegistrationResponse(credential: PublicKeyCredential): RegistrationResponseJson;
declare function encodeAuthenticationResponse(credential: PublicKeyCredential): AuthenticationResponseJson;

declare class PkAuthAdminClient {
    private readonly client;
    constructor(client: ClientOptions);
    getAccount(): Promise<AccountSummary>;
    listCredentials(): Promise<CredentialSummary[]>;
    renameCredential(credentialId: string, label: string): Promise<CredentialSummary>;
    removeCredential(credentialId: string): Promise<void>;
    regenerateBackupCodes(): Promise<BackupCodeBatch>;
    remainingBackupCodes(): Promise<BackupCodeCount>;
    startEmailVerification(email: string): Promise<EmailDispatchResult>;
    completeEmailVerification(token: string): Promise<EmailVerificationResult>;
    startPhoneVerification(phone: string): Promise<PhoneDispatchResult>;
    completePhoneVerification(phone: string, code: string): Promise<PhoneVerificationResult>;
}

/** Convenience facade: a single object exposing both ceremony and admin clients. */
declare class PkAuthClient {
    readonly ceremonies: PkAuthCeremonyClient;
    readonly admin: PkAuthAdminClient;
    constructor(options: ClientOptions, ceremonyOptions?: CeremonyOptions);
}

export { type AccountSummary, type AuthenticationResponseJson, type BackupCodeBatch, type BackupCodeCount, type CeremonyOptions, type ClientOptions, type CredentialSummary, type EmailDispatchResult, type EmailVerificationResult, type FinishAuthenticationRequest, type FinishAuthenticationResponse, type FinishRegistrationParams, type FinishRegistrationRequest, type FinishRegistrationResponse, type PhoneDispatchResult, type PhoneVerificationResult, PkAuthAdminClient, PkAuthCeremonyClient, PkAuthClient, PkAuthHttpError, type PublicKeyCredentialCreationOptionsJson, type PublicKeyCredentialDescriptorJson, type PublicKeyCredentialRequestOptionsJson, type PublicKeyCredentialUserEntityJson, type RegistrationResponseJson, type RpEntity, type StartAuthenticationParams, type StartAuthenticationRequest, type StartAuthenticationResponse, type StartRegistrationParams, type StartRegistrationRequest, type StartRegistrationResponse, type TokenAccessor, base64url, decodeCreationOptions, decodeRequestOptions, encodeAuthenticationResponse, encodeRegistrationResponse };
