/**
 * Tempo Better Auth Plugin Types
 *
 * Type definitions for plugin configuration, endpoints, and client API.
 */

import type { BetterAuthPlugin } from 'better-auth';
import type {
  RegistrationResponseJSON,
  AuthenticationResponseJSON,
  PublicKeyCredentialCreationOptionsJSON,
  PublicKeyCredentialRequestOptionsJSON,
} from '@simplewebauthn/types';

// ============================================================================
// Schema Extension Types
// ============================================================================

/**
 * Field attribute for additionalFields
 * Matches better-auth's DBFieldAttribute structure
 */
export interface FieldAttribute {
  type: 'string' | 'number' | 'boolean' | 'date';
  required?: boolean;
  unique?: boolean;
  defaultValue?: unknown;
  references?: {
    model: string;
    field: string;
    onDelete?: 'cascade' | 'set null' | 'restrict' | 'no action';
  };
  input?: boolean;
}

/**
 * Schema extension config for a single table
 */
export interface TableSchemaConfig {
  modelName?: string;
  fields?: { [key: string]: string };
  additionalFields?: { [key: string]: FieldAttribute };
}

/**
 * Schema extension config for tempo plugin tables
 */
export interface TempoSchemaConfig {
  passkey?: TableSchemaConfig;
  wallet?: TableSchemaConfig;
  accessKey?: TableSchemaConfig;
}

// ============================================================================
// Wallet Types
// ============================================================================

/**
 * Wallet type - how the wallet was created/controlled
 */
export type WalletType = 'passkey' | 'server' | 'external';

/**
 * Key type - cryptographic algorithm used for signing
 */
export type KeyType = 'secp256k1' | 'p256' | 'webauthn';

/**
 * Wallet record (JSON-serializable)
 *
 * Represents any entity that can sign Tempo transactions:
 * - passkey: User's passkey-derived wallet (P256 curve)
 * - server: Backend wallet (Turnkey HSM, KMS, etc.)
 * - external: User's external wallet (MetaMask, WalletConnect, etc.)
 */
export interface Wallet {
  id: string;
  address: string;
  keyType: KeyType;
  walletType: WalletType;
  passkeyId: string | null;
  userId: string | null;
  label: string | null;
  createdAt: string;
}

// ============================================================================
// Plugin Configuration
// ============================================================================

/**
 * Static server wallet configuration
 * Plugin auto-creates a shared wallet on initialization.
 */
export interface StaticServerWallet {
  address: `0x${string}`;
  keyType: KeyType;
  label?: string;
}

/**
 * Dynamic server wallet configuration
 * Plugin calls getAddress() when needed (per-user wallets).
 */
export interface DynamicServerWallet {
  getAddress: (ctx: { userId: string }) => Promise<`0x${string}`>;
  keyType: KeyType;
  label?: string | ((ctx: { userId: string }) => string);
}

export type ServerWalletConfig = StaticServerWallet | DynamicServerWallet;

/**
 * Type guard for static server wallet config
 */
export function isStaticServerWallet(config: ServerWalletConfig): config is StaticServerWallet {
  return 'address' in config;
}

/**
 * Passkey (WebAuthn) configuration
 */
export interface PasskeyConfig {
  /**
   * Relying Party ID - typically the domain (e.g., 'example.com')
   * Defaults to hostname from baseURL
   */
  rpID?: string;

  /**
   * Relying Party name - human-readable name (e.g., 'My App')
   * Defaults to 'App'
   */
  rpName?: string;

  /**
   * Expected origin for WebAuthn verification (e.g., 'https://example.com')
   * Defaults to request origin header
   */
  origin?: string;

  /**
   * Challenge expiration in seconds
   * Default: 300 (5 minutes)
   */
  challengeMaxAge?: number;
}

/**
 * Tempo plugin configuration
 */
export interface TempoPluginConfig {
  /**
   * Server wallet configuration.
   * Static config: Plugin auto-creates a shared wallet on initialization.
   * Dynamic config: Plugin calls getAddress() when needed (per-user wallets).
   */
  serverWallet?: ServerWalletConfig;

  /**
   * Allowed chain IDs for access key creation.
   */
  allowedChainIds?: number[];

  /**
   * Default values for access keys.
   */
  defaults?: {
    accessKeyLabel?: string;
  };

  /**
   * Passkey (WebAuthn) configuration.
   * Required for passkey registration and authentication.
   */
  passkey?: PasskeyConfig;

  /**
   * Schema extensions for tempo plugin tables.
   * Allows adding additional fields to passkey, wallet, and accessKey tables.
   */
  schema?: TempoSchemaConfig;
}

// ============================================================================
// Access Key Types
// ============================================================================

/**
 * Access Key status
 */
export type AccessKeyStatus = 'active' | 'revoked' | 'expired';

/**
 * Access Key type (Tempo protocol)
 */
export type AccessKeyType = 'secp256k1' | 'p256' | 'webauthn';

/**
 * Token spending limit
 *
 * This is the canonical format stored in the authorization.
 * - token: The token contract address
 * - limit: Maximum amount as string (bigint-safe)
 */
export interface TokenLimit {
  token: `0x${string}`;
  limit: string;
}

/**
 * Access Key record (JSON-serializable)
 *
 * Represents authorization from a user's root wallet to another wallet (key).
 * The key wallet can sign transactions on behalf of the user within constraints.
 */
export interface AccessKey {
  id: string;
  userId: string | null;
  rootWalletId: string;
  keyWalletId: string;
  chainId: number;
  expiry: number | null;
  limits: TokenLimit[] | null;
  authorizationSignature: string;
  authorizationHash: string;
  status: AccessKeyStatus;
  revokedAt: string | null;
  label: string | null;
  createdAt: string | null;
  updatedAt?: string | null;
}

/**
 * Access Key with resolved wallet details
 */
export interface AccessKeyWithWallets extends AccessKey {
  rootWallet: Wallet;
  keyWallet: Wallet;
}

// ============================================================================
// Access Key Endpoint Types
// ============================================================================

/**
 * POST /tempo/access-keys - Create Access Key
 */
export interface CreateAccessKeyRequest {
  rootWalletId: string;
  keyWalletId?: string;
  keyWalletAddress?: `0x${string}`;
  chainId: number;
  expiry?: number;
  limits?: TokenLimit[];
  authorizationSignature: string;
  authorizationHash: string;
  label?: string;
}

export interface CreateAccessKeyResponse {
  accessKey: AccessKey;
  rootWallet: Wallet;
  keyWallet: Wallet;
}

/**
 * GET /tempo/access-keys - List Access Keys
 */
export interface ListAccessKeysRequest {
  status?: AccessKeyStatus;
  direction?: 'granted' | 'received';
}

export interface ListAccessKeysResponse {
  accessKeys: AccessKey[];
  direction: 'granted' | 'received';
}

/**
 * GET /tempo/access-keys/:id - Get Access Key
 */
export interface GetAccessKeyResponse {
  accessKey: AccessKey;
  rootWallet: Wallet;
  keyWallet: Wallet;
}

/**
 * DELETE /tempo/access-keys/:id - Revoke Access Key
 */
export interface RevokeAccessKeyRequest {
  reason?: string;
}

export interface RevokeAccessKeyResponse {
  accessKey: AccessKey;
}

// ============================================================================
// Wallet Endpoint Types
// ============================================================================

/**
 * POST /tempo/wallets - Create Wallet
 */
export interface CreateWalletRequest {
  address: `0x${string}`;
  keyType: KeyType;
  walletType: 'server' | 'external'; // passkey wallets are created automatically
  label?: string;
  userId?: string; // For server wallets, null = shared
}

export interface CreateWalletResponse {
  wallet: Wallet;
}

/**
 * GET /tempo/wallets - List Wallets
 */
export interface ListWalletsResponse {
  wallets: Wallet[];
}

/**
 * GET /tempo/wallets/:idOrAddress - Get Wallet
 */
export interface GetWalletResponse {
  wallet: Wallet;
}

/**
 * Passkey record with Tempo address
 */
export interface PasskeyWithAddress {
  id: string;
  userId: string;
  name: string | null;
  credentialID: string;
  publicKey: string;
  publicKeyHex: `0x${string}`; // Raw P-256 coordinates (x || y) for wagmi KeyManager
  tempoAddress: `0x${string}`; // Derived from publicKey
  createdAt: string;
}

/**
 * GET /tempo/passkeys - List Passkeys
 */
export interface ListPasskeysResponse {
  passkeys: PasskeyWithAddress[];
}

/**
 * KeyManager key format (Tempo SDK)
 */
export interface KeyManagerKey {
  credentialId: string;
  publicKey: string; // hex format
  address: string; // Tempo address
}

/**
 * GET /tempo/keymanager - List Keys
 */
export interface ListKeysResponse {
  keys: KeyManagerKey[];
}

/**
 * GET /tempo/keymanager?credentialId=... - Load Key
 */
export interface LoadKeyResponse {
  credentialId: string;
  publicKey: string; // hex format
  address: string; // Tempo address
}

/**
 * POST /tempo/keymanager - Save Key
 */
export interface SaveKeyRequest {
  credentialId: string;
  publicKey: string; // hex format
  address: string; // Tempo address
}

export interface SaveKeyResponse {
  success: boolean;
}

// ============================================================================
// SDK WebAuthn Credential Types (for KeyManager setPublicKey)
// ============================================================================

/**
 * Raw WebAuthn credential response from SDK.
 * This is what the Tempo SDK sends after completing client-side WebAuthn ceremony.
 * Contains attestationObject for registration (not just authenticatorData).
 */
export interface WebAuthnCredentialRaw {
  id: string;
  response: {
    clientDataJSON: string; // base64url encoded
    attestationObject: string; // base64url encoded (contains authenticatorData + attestation)
    transports?: string[]; // optional transport hints
  };
}

/**
 * Decoded clientDataJSON from WebAuthn response.
 * Used to extract the challenge for verification lookup.
 */
export interface ClientDataJSON {
  type: 'webauthn.create' | 'webauthn.get';
  challenge: string; // base64url encoded original challenge
  origin: string;
}

/**
 * Request body for setPublicKey endpoint.
 * SECURITY: The publicKey field is IGNORED - we use verifyRegistrationResponse
 * to extract the validated public key from attestationObject.
 */
export interface SetPublicKeyRequest {
  credential: WebAuthnCredentialRaw;
  publicKey: `0x${string}`; // IGNORED - extracted from verified attestationObject
}

// ============================================================================
// Passkey Endpoint Types
// ============================================================================

/**
 * Passkey record (database format)
 */
export interface PasskeyRecord {
  id: string;
  userId: string;
  name: string | null;
  publicKey: string;
  credentialID: string;
  counter: number;
  deviceType: string | null;
  backedUp: boolean;
  transports: string | null;
  createdAt: Date | string;
}

/**
 * POST /tempo/passkey/register - Register passkey request
 */
export interface RegisterPasskeyRequest {
  response: RegistrationResponseJSON;
  name?: string;
}

/**
 * POST /tempo/passkey/register - Register passkey response
 */
export interface RegisterPasskeyResponse {
  passkey: PasskeyWithAddress;
  wallet: Wallet;
}

/**
 * POST /tempo/passkey/authenticate - Authenticate request
 */
export interface AuthenticatePasskeyRequest {
  response: AuthenticationResponseJSON;
}

/**
 * POST /tempo/passkey/authenticate - Authenticate response
 */
export interface AuthenticatePasskeyResponse {
  session: {
    id: string;
    userId: string;
    expiresAt: Date;
  };
  user: {
    id: string;
    email: string | null;
    name: string | null;
  };
}

/**
 * DELETE /tempo/passkey/:credentialId - Delete passkey response
 */
export interface DeletePasskeyResponse {
  success: boolean;
}

// Re-export simplewebauthn types for client use
export type {
  RegistrationResponseJSON,
  AuthenticationResponseJSON,
  PublicKeyCredentialCreationOptionsJSON,
  PublicKeyCredentialRequestOptionsJSON,
};

// ============================================================================
// Client API Types
// ============================================================================

/**
 * Client-side methods exposed by the plugin
 * Used via: authClient.api.tempo.*
 */
export interface TempoClientAPI {
  // Wallets
  createWallet: (params: CreateWalletRequest) => Promise<CreateWalletResponse>;
  listWallets: () => Promise<ListWalletsResponse>;
  getWallet: (idOrAddress: string) => Promise<GetWalletResponse>;

  // Access Keys
  listAccessKeys: (params?: ListAccessKeysRequest) => Promise<ListAccessKeysResponse>;
  createAccessKey: (params: CreateAccessKeyRequest) => Promise<CreateAccessKeyResponse>;
  getAccessKey: (id: string) => Promise<GetAccessKeyResponse>;
  revokeAccessKey: (id: string) => Promise<RevokeAccessKeyResponse>;

  // Passkeys (WebAuthn)
  getPasskeyRegistrationOptions: () => Promise<PublicKeyCredentialCreationOptionsJSON>;
  registerPasskey: (params: RegisterPasskeyRequest) => Promise<RegisterPasskeyResponse>;
  getPasskeyAuthenticationOptions: () => Promise<PublicKeyCredentialRequestOptionsJSON>;
  authenticateWithPasskey: (
    params: AuthenticatePasskeyRequest
  ) => Promise<AuthenticatePasskeyResponse>;
  listPasskeys: () => Promise<ListPasskeysResponse>;
  deletePasskey: (credentialId: string) => Promise<DeletePasskeyResponse>;

  // KeyManager
  listKeys: () => Promise<ListKeysResponse>;
  loadKey: (credentialId: string) => Promise<LoadKeyResponse>;
  saveKey: (params: SaveKeyRequest) => Promise<SaveKeyResponse>;
}

// ============================================================================
// Plugin Type Export
// ============================================================================

/**
 * Tempo plugin factory type
 */
export type TempoPlugin = (config: TempoPluginConfig) => BetterAuthPlugin;
