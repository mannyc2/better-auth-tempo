/**
 * Tempo Plugin Routes
 *
 * Endpoint definitions for Wallets, Access Keys, and Passkeys.
 * All endpoints use the better-auth adapter pattern for database portability.
 */

import {
  APIError,
  createAuthEndpoint,
  sensitiveSessionMiddleware,
  sessionMiddleware,
} from 'better-auth/api';
import { setSessionCookie } from 'better-auth/cookies';
import {
  generateRegistrationOptions,
  verifyRegistrationResponse,
  generateAuthenticationOptions,
  verifyAuthenticationResponse,
} from '@simplewebauthn/server';
import type { AuthenticatorTransportFuture } from '@simplewebauthn/types';
import { isoBase64URL } from '@simplewebauthn/server/helpers';
import { TEMPO_ERROR_CODES } from './error-codes';
import {
  deriveTempoAddress,
  deriveTempoAddressFromHex,
  getPublicKeyHex,
  isHexPublicKey,
  hexToCose,
} from './utils';
import type {
  AccessKey,
  AccessKeyStatus,
  AuthenticatePasskeyRequest,
  AuthenticatePasskeyResponse,
  CreateAccessKeyRequest,
  CreateAccessKeyResponse,
  CreateWalletRequest,
  DeletePasskeyResponse,
  GetAccessKeyResponse,
  KeyType,
  ListAccessKeysResponse,
  PasskeyRecord,
  PasskeyWithAddress,
  RegisterPasskeyRequest,
  RegisterPasskeyResponse,
  RevokeAccessKeyResponse,
  TempoPluginConfig,
  TokenLimit,
  Wallet,
  WalletType,
} from './types';

// ============================================================================
// HELPERS
// ============================================================================

/**
 * Convert standard base64 to base64url encoding.
 * better-auth stores publicKey in standard base64, but isoBase64URL expects base64url.
 */
function base64ToBase64url(base64: string): string {
  return base64.replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

// ============================================================================
// PASSKEY ENDPOINTS
// ============================================================================

/**
 * GET /tempo/passkeys - List user's passkeys with Tempo addresses
 *
 * Lists all passkeys for the user with their derived Tempo blockchain addresses.
 * Use this to find passkeys that can sign blockchain transactions.
 */
export const listTempoPasskeys = createAuthEndpoint(
  '/tempo/passkeys',
  {
    method: 'GET',
    use: [sessionMiddleware],
    metadata: {
      openapi: {
        operationId: 'listTempoPasskeys',
        description: 'List all passkeys with their Tempo blockchain addresses',
        responses: {
          '200': {
            description: 'Passkeys retrieved successfully',
            content: {
              'application/json': {
                schema: {
                  type: 'array',
                  items: {
                    $ref: '#/components/schemas/PasskeyWithAddress',
                  },
                  description: 'Array of passkeys with Tempo addresses',
                },
              },
            },
          },
        },
      },
    },
  },
  async (ctx) => {
    const rawPasskeys = await ctx.context.adapter.findMany<PasskeyRecord>({
      model: 'passkey',
      where: [{ field: 'userId', value: ctx.context.session.user.id }],
      sortBy: { field: 'createdAt', direction: 'desc' },
    });

    // Derive publicKeyHex and tempoAddress from publicKey for each passkey
    const passkeys: PasskeyWithAddress[] = rawPasskeys.map((p) => {
      const publicKeyHex = getPublicKeyHex(p.publicKey);
      return {
        id: p.id,
        userId: p.userId,
        name: p.name,
        credentialID: p.credentialID,
        publicKey: p.publicKey,
        publicKeyHex,
        tempoAddress: deriveTempoAddressFromHex(publicKeyHex),
        createdAt: typeof p.createdAt === 'string' ? p.createdAt : p.createdAt.toISOString(),
      };
    });

    return ctx.json(passkeys, { status: 200 });
  }
);

// ============================================================================
// PASSKEY REGISTRATION & AUTHENTICATION ENDPOINTS
// ============================================================================

/**
 * Helper to generate random string for challenge tokens
 */
function generateRandomString(length: number): string {
  const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
  let result = '';
  const randomValues = new Uint8Array(length);
  crypto.getRandomValues(randomValues);
  for (let i = 0; i < length; i++) {
    result += chars[randomValues[i] % chars.length];
  }
  return result;
}

/**
 * GET /tempo/passkey/register-options - Generate registration options
 *
 * Generates WebAuthn registration options for passkey creation.
 * Only ES256 (P-256) is allowed for Tempo blockchain compatibility.
 */
export const getPasskeyRegistrationOptions = (config: TempoPluginConfig) =>
  createAuthEndpoint(
    '/tempo/passkey/register-options',
    {
      method: 'GET',
      use: [sessionMiddleware],
      metadata: {
        openapi: {
          operationId: 'getPasskeyRegistrationOptions',
          description: 'Generate WebAuthn registration options for passkey creation',
          responses: {
            '200': {
              description: 'Registration options generated successfully',
            },
          },
        },
      },
    },
    async (ctx) => {
      const { session } = ctx.context;

      // Get existing passkeys to exclude
      const existingPasskeys = await ctx.context.adapter.findMany<PasskeyRecord>({
        model: 'passkey',
        where: [{ field: 'userId', value: session.user.id }],
      });

      const rpID =
        config.passkey?.rpID || new URL(ctx.context.options.baseURL || 'http://localhost').hostname;
      const rpName = config.passkey?.rpName || 'App';

      const options = await generateRegistrationOptions({
        rpName,
        rpID,
        userID: new TextEncoder().encode(session.user.id),
        userName: session.user.email || session.user.id,
        userDisplayName: session.user.name || session.user.email || session.user.id,
        attestationType: 'none',
        authenticatorSelection: {
          residentKey: 'preferred',
          userVerification: 'preferred',
        },
        supportedAlgorithmIDs: [-7], // ES256 only for Tempo
        excludeCredentials: existingPasskeys.map((p) => ({
          id: p.credentialID,
          transports: p.transports?.split(',') as AuthenticatorTransportFuture[],
        })),
      });

      // Store challenge in verification table
      const challengeToken = generateRandomString(32);
      const challengeMaxAge = config.passkey?.challengeMaxAge || 300;

      await ctx.context.internalAdapter.createVerificationValue({
        identifier: challengeToken,
        value: JSON.stringify({
          challenge: options.challenge,
          userId: session.user.id,
        }),
        expiresAt: new Date(Date.now() + challengeMaxAge * 1000),
      });

      // Set challenge cookie
      const cookie = ctx.context.createAuthCookie('tempo_passkey_challenge');
      await ctx.setSignedCookie(cookie.name, challengeToken, ctx.context.secret, {
        ...cookie.attributes,
        maxAge: challengeMaxAge,
      });

      return ctx.json(options);
    }
  );

/**
 * POST /tempo/passkey/register - Verify registration and create passkey + wallet
 *
 * Verifies the WebAuthn registration response server-side and atomically
 * creates both the passkey record and derived Tempo wallet.
 */
export const verifyPasskeyRegistration = (config: TempoPluginConfig) =>
  createAuthEndpoint(
    '/tempo/passkey/register',
    {
      method: 'POST',
      use: [sessionMiddleware],
      metadata: {
        openapi: {
          operationId: 'verifyPasskeyRegistration',
          description: 'Verify registration and create passkey + wallet atomically',
          responses: {
            '200': { description: 'Passkey and wallet created successfully' },
            '400': { description: 'Verification failed' },
          },
        },
      },
    },
    async (ctx) => {
      const { session } = ctx.context;
      const body = ctx.body as RegisterPasskeyRequest;

      if (!body?.response) {
        throw new APIError('BAD_REQUEST', { message: 'WebAuthn response required' });
      }

      // Get challenge from cookie
      const cookie = ctx.context.createAuthCookie('tempo_passkey_challenge');
      const challengeToken = await ctx.getSignedCookie(cookie.name, ctx.context.secret);

      if (!challengeToken) {
        throw new APIError('BAD_REQUEST', { message: 'Challenge not found or expired' });
      }

      // Get stored challenge
      const stored = await ctx.context.internalAdapter.findVerificationValue(challengeToken);
      if (!stored) {
        throw new APIError('BAD_REQUEST', { message: 'Challenge expired' });
      }

      const { challenge, userId } = JSON.parse(stored.value);
      if (userId !== session.user.id) {
        throw new APIError('FORBIDDEN', { message: 'Challenge mismatch' });
      }

      // Verify with SimpleWebAuthn (server-side validation)
      const origin = config.passkey?.origin || ctx.headers?.get('origin') || '';
      const rpID =
        config.passkey?.rpID || new URL(ctx.context.options.baseURL || 'http://localhost').hostname;

      const verification = await verifyRegistrationResponse({
        response: body.response,
        expectedChallenge: challenge,
        expectedOrigin: origin,
        expectedRPID: rpID,
        requireUserVerification: false,
      });

      if (!verification.verified || !verification.registrationInfo) {
        throw new APIError('BAD_REQUEST', { message: 'Verification failed' });
      }

      const { credential, credentialDeviceType, credentialBackedUp } =
        verification.registrationInfo;

      // Store passkey with base64-encoded public key (COSE format)
      const publicKeyBase64 = isoBase64URL.fromBuffer(credential.publicKey);

      const passkey = await ctx.context.adapter.create<PasskeyRecord>({
        model: 'passkey',
        data: {
          userId: session.user.id,
          credentialID: credential.id,
          publicKey: publicKeyBase64,
          counter: credential.counter,
          deviceType: credentialDeviceType,
          backedUp: credentialBackedUp,
          transports: body.response.response.transports?.join(',') || null,
          name: body.name || null,
          createdAt: new Date(),
        },
      });

      // Create wallet ATOMICALLY with passkey
      const tempoAddress = deriveTempoAddress(publicKeyBase64);

      const wallet = (await ctx.context.adapter.create({
        model: 'wallet',
        data: {
          address: tempoAddress,
          keyType: 'p256',
          walletType: 'passkey',
          passkeyId: passkey.id,
          userId: session.user.id,
          label: body.name || 'Passkey Wallet',
          createdAt: new Date(),
        },
      })) as WalletRecord;

      // Cleanup verification value
      await ctx.context.internalAdapter.deleteVerificationValue(stored.id);

      // Clear challenge cookie
      ctx.setCookie(cookie.name, '', { ...cookie.attributes, maxAge: 0 });

      return ctx.json({
        passkey: {
          id: passkey.id,
          userId: passkey.userId,
          name: passkey.name,
          credentialID: passkey.credentialID,
          publicKey: passkey.publicKey,
          tempoAddress,
          createdAt:
            typeof passkey.createdAt === 'string'
              ? passkey.createdAt
              : passkey.createdAt.toISOString(),
        },
        wallet: serializeWallet(wallet),
      } as RegisterPasskeyResponse);
    }
  );

/**
 * GET /tempo/passkey/authenticate-options - Generate authentication options
 *
 * Generates WebAuthn authentication options for passkey login.
 * No session required since this IS the login flow.
 */
export const getPasskeyAuthenticationOptions = (config: TempoPluginConfig) =>
  createAuthEndpoint(
    '/tempo/passkey/authenticate-options',
    {
      method: 'GET',
      metadata: {
        openapi: {
          operationId: 'getPasskeyAuthenticationOptions',
          description: 'Generate WebAuthn authentication options for login',
          responses: {
            '200': { description: 'Authentication options generated successfully' },
          },
        },
      },
    },
    async (ctx) => {
      const rpID =
        config.passkey?.rpID || new URL(ctx.context.options.baseURL || 'http://localhost').hostname;

      const options = await generateAuthenticationOptions({
        rpID,
        userVerification: 'preferred',
        // Empty allowCredentials = discoverable credentials (passkeys stored on device)
      });

      // Store challenge
      const challengeToken = generateRandomString(32);
      const challengeMaxAge = config.passkey?.challengeMaxAge || 300;

      await ctx.context.internalAdapter.createVerificationValue({
        identifier: challengeToken,
        value: JSON.stringify({ challenge: options.challenge }),
        expiresAt: new Date(Date.now() + challengeMaxAge * 1000),
      });

      const cookie = ctx.context.createAuthCookie('tempo_passkey_challenge');
      await ctx.setSignedCookie(cookie.name, challengeToken, ctx.context.secret, {
        ...cookie.attributes,
        maxAge: challengeMaxAge,
      });

      return ctx.json(options);
    }
  );

/**
 * POST /tempo/passkey/authenticate - Verify authentication and create session
 *
 * Verifies the WebAuthn authentication response and creates a session.
 */
export const verifyPasskeyAuthentication = (config: TempoPluginConfig) =>
  createAuthEndpoint(
    '/tempo/passkey/authenticate',
    {
      method: 'POST',
      metadata: {
        openapi: {
          operationId: 'verifyPasskeyAuthentication',
          description: 'Verify authentication and create session',
          responses: {
            '200': { description: 'Session created successfully' },
            '400': { description: 'Verification failed' },
            '404': { description: 'Passkey not found' },
          },
        },
      },
    },
    async (ctx) => {
      const body = ctx.body as AuthenticatePasskeyRequest;

      if (!body?.response) {
        throw new APIError('BAD_REQUEST', { message: 'WebAuthn response required' });
      }

      // Get challenge from cookie
      const cookie = ctx.context.createAuthCookie('tempo_passkey_challenge');
      const challengeToken = await ctx.getSignedCookie(cookie.name, ctx.context.secret);

      if (!challengeToken) {
        throw new APIError('BAD_REQUEST', { message: 'Challenge not found or expired' });
      }

      const stored = await ctx.context.internalAdapter.findVerificationValue(challengeToken);
      if (!stored) {
        throw new APIError('BAD_REQUEST', { message: 'Challenge expired' });
      }

      const { challenge } = JSON.parse(stored.value);

      // Find passkey by credential ID
      const passkeys = await ctx.context.adapter.findMany<PasskeyRecord>({
        model: 'passkey',
        where: [{ field: 'credentialID', value: body.response.id }],
        limit: 1,
      });

      const passkey = passkeys[0];
      if (!passkey) {
        throw new APIError('NOT_FOUND', { message: 'Passkey not found' });
      }

      // Verify with SimpleWebAuthn
      const origin = config.passkey?.origin || ctx.headers?.get('origin') || '';
      const rpID =
        config.passkey?.rpID || new URL(ctx.context.options.baseURL || 'http://localhost').hostname;

      // Convert stored public key to COSE bytes for verification
      // Handle both formats: hex (from SDK) and base64 COSE (from @simplewebauthn)
      let publicKeyBytes: Uint8Array;
      if (isHexPublicKey(passkey.publicKey)) {
        // Hex format from SDK - convert to COSE bytes
        const coseBase64 = hexToCose(passkey.publicKey);
        const binaryString = atob(coseBase64);
        publicKeyBytes = new Uint8Array(binaryString.length);
        for (let i = 0; i < binaryString.length; i++) {
          publicKeyBytes[i] = binaryString.charCodeAt(i);
        }
      } else {
        // Base64 COSE format from @simplewebauthn
        publicKeyBytes = isoBase64URL.toBuffer(base64ToBase64url(passkey.publicKey));
      }

      const verification = await verifyAuthenticationResponse({
        response: body.response,
        expectedChallenge: challenge,
        expectedOrigin: origin,
        expectedRPID: rpID,
        credential: {
          id: passkey.credentialID,
          publicKey: publicKeyBytes as Uint8Array<ArrayBuffer>,
          counter: passkey.counter,
          transports: passkey.transports?.split(',') as AuthenticatorTransportFuture[],
        },
        requireUserVerification: false,
      });

      if (!verification.verified) {
        throw new APIError('UNAUTHORIZED', { message: 'Authentication failed' });
      }

      // Update counter
      await ctx.context.adapter.update({
        model: 'passkey',
        where: [{ field: 'id', value: passkey.id }],
        update: { counter: verification.authenticationInfo.newCounter },
      });

      // Create session
      const session = await ctx.context.internalAdapter.createSession(passkey.userId);
      const user = await ctx.context.internalAdapter.findUserById(passkey.userId);

      if (!session || !user) {
        throw new APIError('INTERNAL_SERVER_ERROR', { message: 'Session creation failed' });
      }

      // Set session cookie
      await setSessionCookie(ctx, { session, user });

      // Cleanup verification value
      await ctx.context.internalAdapter.deleteVerificationValue(stored.id);

      // Clear challenge cookie
      ctx.setCookie(cookie.name, '', { ...cookie.attributes, maxAge: 0 });

      return ctx.json({
        session: {
          id: session.id,
          userId: session.userId,
          expiresAt: session.expiresAt,
        },
        user: {
          id: user.id,
          email: user.email,
          name: user.name,
        },
      } as AuthenticatePasskeyResponse);
    }
  );

/**
 * DELETE /tempo/passkey/:credentialId - Delete passkey
 *
 * Deletes a passkey and its associated wallet (via FK cascade).
 * Uses WebAuthn credentialID for consistency with other passkey routes.
 */
export const deletePasskey = createAuthEndpoint(
  '/tempo/passkey/:credentialId',
  {
    method: 'DELETE',
    use: [sessionMiddleware],
    metadata: {
      openapi: {
        operationId: 'deletePasskey',
        description: 'Delete a passkey (wallet cascades via FK)',
        responses: {
          '200': { description: 'Passkey deleted successfully' },
          '403': { description: 'Not your passkey' },
          '404': { description: 'Passkey not found' },
        },
      },
    },
  },
  async (ctx) => {
    const { session } = ctx.context;
    const credentialId = ctx.params?.credentialId;

    if (!credentialId) {
      throw new APIError('BAD_REQUEST', { message: TEMPO_ERROR_CODES.MISSING_CREDENTIAL_ID });
    }

    const passkeys = await ctx.context.adapter.findMany<PasskeyRecord>({
      model: 'passkey',
      where: [{ field: 'credentialID', value: credentialId }],
      limit: 1,
    });

    const passkey = passkeys[0];
    if (!passkey) {
      throw new APIError('NOT_FOUND', { message: 'Passkey not found' });
    }

    if (passkey.userId !== session.user.id) {
      throw new APIError('FORBIDDEN', { message: 'Not your passkey' });
    }

    // Delete passkey (wallet cascades via FK)
    await ctx.context.adapter.delete({
      model: 'passkey',
      where: [{ field: 'id', value: passkey.id }],
    });

    return ctx.json({ success: true } as DeletePasskeyResponse);
  }
);

// ============================================================================
// WALLET ENDPOINTS (New - uses adapter pattern)
// ============================================================================

/**
 * Internal wallet record from database
 */
interface WalletRecord {
  id: string;
  address: string;
  keyType: string;
  walletType: string;
  passkeyId: string | null;
  userId: string | null;
  label: string | null;
  createdAt: Date;
}

/**
 * Serialize wallet record to API response format
 */
function serializeWallet(wallet: WalletRecord): Wallet {
  return {
    id: wallet.id,
    address: wallet.address,
    keyType: wallet.keyType as KeyType,
    walletType: wallet.walletType as WalletType,
    passkeyId: wallet.passkeyId,
    userId: wallet.userId,
    label: wallet.label,
    createdAt: wallet.createdAt instanceof Date ? wallet.createdAt.toISOString() : wallet.createdAt,
  };
}

/**
 * GET /tempo/wallets - List Wallets
 *
 * Returns the user's own wallets:
 * - Passkey wallets
 * - External wallets
 * - User-specific server wallets
 */
export const listWallets = createAuthEndpoint(
  '/tempo/wallets',
  {
    method: 'GET',
    use: [sessionMiddleware],
    metadata: {
      openapi: {
        operationId: 'listWallets',
        description: 'List wallets for the authenticated user',
        responses: {
          '200': {
            description: 'Wallets retrieved successfully',
          },
        },
      },
    },
  },
  async (ctx) => {
    const { session } = ctx.context;

    // User's own wallets only (passkey, external, or user-specific server wallets)
    const userWallets = await ctx.context.adapter.findMany<WalletRecord>({
      model: 'wallet',
      where: [{ field: 'userId', value: session.user.id }],
      sortBy: { field: 'createdAt', direction: 'desc' },
    });

    return ctx.json({ wallets: userWallets.map(serializeWallet) });
  }
);

/**
 * GET /tempo/server-wallet - Get Server Wallet
 *
 * Returns the shared server wallet used for Access Key authorization.
 * This is the wallet address that users authorize to sign on their behalf.
 */
export const getServerWallet = createAuthEndpoint(
  '/tempo/server-wallet',
  {
    method: 'GET',
    use: [sessionMiddleware],
    metadata: {
      openapi: {
        operationId: 'getServerWallet',
        description: 'Get the server wallet for Access Key authorization',
        responses: {
          '200': { description: 'Server wallet retrieved successfully' },
          '404': { description: 'Server wallet not configured' },
        },
      },
    },
  },
  async (ctx) => {
    // Find the shared server wallet (userId = null, walletType = server)
    const serverWallets = await ctx.context.adapter.findMany<WalletRecord>({
      model: 'wallet',
      where: [{ field: 'walletType', value: 'server' }],
    });
    const serverWallet = serverWallets.find((w) => w.userId === null);

    if (!serverWallet) {
      throw new APIError('NOT_FOUND', { message: 'Server wallet not configured' });
    }

    return ctx.json({ wallet: serializeWallet(serverWallet) });
  }
);

/**
 * GET /tempo/wallets/:idOrAddress - Get Wallet
 *
 * Retrieves a wallet by ID or address.
 */
export const getWallet = createAuthEndpoint(
  '/tempo/wallets/:idOrAddress',
  {
    method: 'GET',
    use: [sessionMiddleware],
    metadata: {
      openapi: {
        operationId: 'getWallet',
        description: 'Get a wallet by ID or address',
        responses: {
          '200': { description: 'Wallet retrieved successfully' },
          '404': { description: 'Wallet not found' },
        },
      },
    },
  },
  async (ctx) => {
    const idOrAddress = ctx.params?.idOrAddress as string;
    if (!idOrAddress) {
      throw new APIError('BAD_REQUEST', { message: 'Wallet ID or address required' });
    }

    // Try by ID first
    let wallets = await ctx.context.adapter.findMany<WalletRecord>({
      model: 'wallet',
      where: [{ field: 'id', value: idOrAddress }],
      limit: 1,
    });

    // If not found and looks like address, try by address
    if (wallets.length === 0 && idOrAddress.startsWith('0x')) {
      wallets = await ctx.context.adapter.findMany<WalletRecord>({
        model: 'wallet',
        where: [{ field: 'address', value: idOrAddress }],
        limit: 1,
      });
    }

    if (wallets.length === 0) {
      throw new APIError('NOT_FOUND', { message: 'Wallet not found' });
    }

    return ctx.json({ wallet: serializeWallet(wallets[0]) });
  }
);

/**
 * POST /tempo/wallets - Create Wallet
 *
 * For registering server wallets or external wallets.
 * Passkey wallets are created automatically via hook.
 */
export const createWallet = createAuthEndpoint(
  '/tempo/wallets',
  {
    method: 'POST',
    use: [sessionMiddleware],
    metadata: {
      openapi: {
        operationId: 'createWallet',
        description: 'Create a server or external wallet',
        responses: {
          '200': { description: 'Wallet created successfully' },
          '400': { description: 'Invalid request' },
          '409': { description: 'Wallet already exists' },
        },
      },
    },
  },
  async (ctx) => {
    const { session } = ctx.context;
    const body = ctx.body as CreateWalletRequest;

    if (!body?.address || !body?.keyType || !body?.walletType) {
      throw new APIError('BAD_REQUEST', { message: 'address, keyType, and walletType required' });
    }

    // Validate walletType
    if (!['server', 'external'].includes(body.walletType)) {
      throw new APIError('BAD_REQUEST', {
        message:
          'walletType must be "server" or "external". Passkey wallets are created automatically.',
      });
    }

    // Check address uniqueness
    const existing = await ctx.context.adapter.findMany<WalletRecord>({
      model: 'wallet',
      where: [{ field: 'address', value: body.address }],
      limit: 1,
    });

    if (existing.length > 0) {
      throw new APIError('CONFLICT', { message: 'Wallet with this address already exists' });
    }

    // Determine userId based on wallet type
    let userId: string | null = null;
    if (body.walletType === 'external') {
      // External wallets always belong to current user
      userId = session.user.id;
    } else if (body.walletType === 'server') {
      // Server wallets: explicit userId or null (shared)
      userId = body.userId || null;
    }

    const wallet = await ctx.context.adapter.create<WalletRecord>({
      model: 'wallet',
      data: {
        address: body.address,
        keyType: body.keyType,
        walletType: body.walletType,
        passkeyId: null,
        userId,
        label: body.label || null,
        createdAt: new Date(),
      },
    });

    return ctx.json({ wallet: serializeWallet(wallet) });
  }
);

// ============================================================================
// ACCESS KEY ENDPOINTS (wallet-based, uses adapter pattern)
// ============================================================================

/**
 * Internal access key record from database
 */
interface AccessKeyRecord {
  id: string;
  userId: string;
  rootWalletId: string | null;
  keyWalletId: string | null;
  chainId: number;
  expiry: number | null;
  limits: string | null;
  authorizationSignature: string;
  authorizationHash: string;
  status: string;
  label: string | null;
  revokedAt: Date | null;
  createdAt: Date;
  updatedAt?: Date | null;
}

/**
 * Serialize access key record to API response format
 */
function serializeAccessKeyRecord(record: AccessKeyRecord): AccessKey {
  // Parse limits from JSON string
  let limits: TokenLimit[] | null = null;
  if (record.limits) {
    try {
      const parsed = JSON.parse(record.limits);
      if (Array.isArray(parsed)) {
        limits = parsed as TokenLimit[];
      }
    } catch {
      limits = null;
    }
  }

  return {
    id: record.id,
    userId: record.userId,
    rootWalletId: record.rootWalletId || '',
    keyWalletId: record.keyWalletId || '',
    chainId: record.chainId,
    expiry: record.expiry ?? null,
    limits,
    authorizationSignature: record.authorizationSignature,
    authorizationHash: record.authorizationHash,
    status: record.status as AccessKeyStatus,
    label: record.label,
    revokedAt: record.revokedAt instanceof Date ? record.revokedAt.toISOString() : record.revokedAt,
    createdAt:
      record.createdAt instanceof Date
        ? record.createdAt.toISOString()
        : ((record.createdAt as unknown as string) ?? null),
    updatedAt:
      record.updatedAt instanceof Date
        ? record.updatedAt.toISOString()
        : ((record.updatedAt as unknown as string) ?? null),
  };
}

/**
 * POST /tempo/access-keys - Create Access Key (V2)
 *
 * Creates a new access key using wallet IDs instead of addresses.
 * Uses adapter pattern for portability.
 */
export const createAccessKey = (config: TempoPluginConfig) =>
  createAuthEndpoint(
    '/tempo/access-keys',
    {
      method: 'POST',
      use: [sensitiveSessionMiddleware],
      metadata: {
        openapi: {
          operationId: 'createAccessKey',
          description: 'Create a new access key (wallet-based)',
          responses: {
            '200': { description: 'Access key created successfully' },
            '400': { description: 'Invalid request' },
            '404': { description: 'Wallet not found' },
          },
        },
      },
    },
    async (ctx) => {
      const { session } = ctx.context;
      const body = ctx.body as CreateAccessKeyRequest;

      if (!body) {
        throw new APIError('BAD_REQUEST', { message: TEMPO_ERROR_CODES.INVALID_REQUEST });
      }

      const { rootWalletId, keyWalletId, keyWalletAddress, chainId } = body;

      if (!rootWalletId || !chainId) {
        throw new APIError('BAD_REQUEST', { message: 'rootWalletId and chainId required' });
      }

      if (!keyWalletId && !keyWalletAddress) {
        throw new APIError('BAD_REQUEST', {
          message: 'Either keyWalletId or keyWalletAddress required',
        });
      }

      // Validate chain ID
      if (config.allowedChainIds && !config.allowedChainIds.includes(chainId)) {
        throw new APIError('BAD_REQUEST', {
          message: `${TEMPO_ERROR_CODES.INVALID_CHAIN_ID}. Allowed: ${config.allowedChainIds.join(', ')}`,
        });
      }

      // Resolve root wallet (must belong to current user)
      const rootWallets = await ctx.context.adapter.findMany<WalletRecord>({
        model: 'wallet',
        where: [{ field: 'id', value: rootWalletId }],
        limit: 1,
      });

      if (rootWallets.length === 0) {
        throw new APIError('NOT_FOUND', { message: 'Root wallet not found' });
      }

      const rootWallet = rootWallets[0];
      if (rootWallet.userId !== session.user.id) {
        throw new APIError('FORBIDDEN', { message: 'Root wallet not owned by user' });
      }

      // Resolve key wallet
      let keyWallet: WalletRecord | null = null;

      if (keyWalletId) {
        const wallets = await ctx.context.adapter.findMany<WalletRecord>({
          model: 'wallet',
          where: [{ field: 'id', value: keyWalletId }],
          limit: 1,
        });
        keyWallet = wallets[0] || null;
      } else if (keyWalletAddress) {
        const wallets = await ctx.context.adapter.findMany<WalletRecord>({
          model: 'wallet',
          where: [{ field: 'address', value: keyWalletAddress }],
          limit: 1,
        });
        keyWallet = wallets[0] || null;
      }

      if (!keyWallet) {
        throw new APIError('NOT_FOUND', {
          message: 'Key wallet not found. Create it first via POST /tempo/wallets.',
        });
      }

      // Create access key
      const now = new Date().toISOString();
      const accessKey = (await ctx.context.adapter.create({
        model: 'accessKey',
        data: {
          userId: session.user.id,
          rootWalletId: rootWallet.id,
          keyWalletId: keyWallet.id,
          chainId,
          expiry: body.expiry ?? null,
          limits: body.limits ? JSON.stringify(body.limits) : null,
          authorizationSignature: body.authorizationSignature,
          authorizationHash: body.authorizationHash,
          status: 'active',
          label: body.label || config.defaults?.accessKeyLabel || null,
          revokedAt: null,
          createdAt: now,
          updatedAt: now,
        },
      })) as AccessKeyRecord;

      return ctx.json({
        accessKey: serializeAccessKeyRecord(accessKey),
        rootWallet: serializeWallet(rootWallet),
        keyWallet: serializeWallet(keyWallet),
      } as CreateAccessKeyResponse);
    }
  );

/**
 * GET /tempo/access-keys - List Access Keys (V2)
 *
 * Lists access keys with wallet information.
 * Query params:
 * - direction=granted (default): Access keys I've granted
 * - direction=received: Access keys granted to my wallets
 */
export const listAccessKeys = createAuthEndpoint(
  '/tempo/access-keys',
  {
    method: 'GET',
    use: [sessionMiddleware],
    metadata: {
      openapi: {
        operationId: 'listAccessKeys',
        description: 'List access keys (wallet-based)',
        responses: {
          '200': { description: 'Access keys retrieved successfully' },
        },
      },
    },
  },
  async (ctx) => {
    const { session } = ctx.context;

    const url = new URL(ctx.request?.url || 'http://localhost');
    const direction = url.searchParams.get('direction') || 'granted';

    if (direction === 'granted') {
      // Access keys I've granted
      const accessKeys = await ctx.context.adapter.findMany<AccessKeyRecord>({
        model: 'accessKey',
        where: [
          { field: 'userId', value: session.user.id },
          { field: 'status', value: 'active' },
        ],
        sortBy: { field: 'createdAt', direction: 'desc' },
      });

      return ctx.json({
        accessKeys: accessKeys.map(serializeAccessKeyRecord),
        direction: 'granted',
      } as ListAccessKeysResponse);
    }

    if (direction === 'received') {
      // Access keys granted to my wallets
      const myWallets = await ctx.context.adapter.findMany<WalletRecord>({
        model: 'wallet',
        where: [{ field: 'userId', value: session.user.id }],
      });

      if (myWallets.length === 0) {
        return ctx.json({
          accessKeys: [],
          direction: 'received',
        } as ListAccessKeysResponse);
      }

      const myWalletIds = myWallets.map((w) => w.id);

      // Find active access keys and filter by key wallet
      const allActiveKeys = await ctx.context.adapter.findMany<AccessKeyRecord>({
        model: 'accessKey',
        where: [{ field: 'status', value: 'active' }],
      });

      const accessKeys = allActiveKeys.filter(
        (ak) => ak.keyWalletId && myWalletIds.includes(ak.keyWalletId)
      );

      return ctx.json({
        accessKeys: accessKeys.map(serializeAccessKeyRecord),
        direction: 'received',
      } as ListAccessKeysResponse);
    }

    throw new APIError('BAD_REQUEST', {
      message: 'direction must be "granted" or "received"',
    });
  }
);

/**
 * GET /tempo/access-keys/:id - Get Access Key (V2)
 *
 * Retrieves a specific access key with wallet details.
 */
export const getAccessKey = createAuthEndpoint(
  '/tempo/access-keys/:id',
  {
    method: 'GET',
    use: [sessionMiddleware],
    metadata: {
      openapi: {
        operationId: 'getAccessKey',
        description: 'Get a specific access key (wallet-based)',
        responses: {
          '200': { description: 'Access key retrieved successfully' },
          '403': { description: 'Access denied' },
          '404': { description: 'Access key not found' },
        },
      },
    },
  },
  async (ctx) => {
    const { session } = ctx.context;
    const id = ctx.params?.id as string;

    if (!id) {
      throw new APIError('BAD_REQUEST', { message: TEMPO_ERROR_CODES.ACCESS_KEY_ID_REQUIRED });
    }

    const accessKeys = await ctx.context.adapter.findMany<AccessKeyRecord>({
      model: 'accessKey',
      where: [{ field: 'id', value: id }],
      limit: 1,
    });

    if (accessKeys.length === 0) {
      throw new APIError('NOT_FOUND', { message: TEMPO_ERROR_CODES.ACCESS_KEY_NOT_FOUND });
    }

    const accessKey = accessKeys[0];

    // Get key wallet
    let keyWallet: WalletRecord | null = null;
    if (accessKey.keyWalletId) {
      const wallets = await ctx.context.adapter.findMany<WalletRecord>({
        model: 'wallet',
        where: [{ field: 'id', value: accessKey.keyWalletId }],
        limit: 1,
      });
      keyWallet = wallets[0] || null;
    }

    // Authorization: must be root wallet owner OR key wallet owner
    const isRootOwner = accessKey.userId === session.user.id;
    const isKeyOwner = keyWallet?.userId === session.user.id;

    if (!isRootOwner && !isKeyOwner) {
      throw new APIError('FORBIDDEN', { message: TEMPO_ERROR_CODES.ACCESS_DENIED });
    }

    return ctx.json({
      accessKey: serializeAccessKeyRecord(accessKey),
      keyWallet: keyWallet ? serializeWallet(keyWallet) : null,
    } as GetAccessKeyResponse);
  }
);

/**
 * DELETE /tempo/access-keys/:id - Revoke Access Key (V2)
 *
 * Revokes an access key. Only the granter can revoke.
 */
export const revokeAccessKey = createAuthEndpoint(
  '/tempo/access-keys/:id',
  {
    method: 'DELETE',
    use: [sensitiveSessionMiddleware],
    metadata: {
      openapi: {
        operationId: 'revokeAccessKey',
        description: 'Revoke an access key',
        responses: {
          '200': { description: 'Access key revoked successfully' },
          '400': { description: 'Already revoked' },
          '403': { description: 'Only granter can revoke' },
          '404': { description: 'Access key not found' },
        },
      },
    },
  },
  async (ctx) => {
    const { session } = ctx.context;
    const id = ctx.params?.id as string;

    if (!id) {
      throw new APIError('BAD_REQUEST', { message: TEMPO_ERROR_CODES.ACCESS_KEY_ID_REQUIRED });
    }

    const accessKeys = await ctx.context.adapter.findMany<AccessKeyRecord>({
      model: 'accessKey',
      where: [{ field: 'id', value: id }],
      limit: 1,
    });

    if (accessKeys.length === 0) {
      throw new APIError('NOT_FOUND', { message: TEMPO_ERROR_CODES.ACCESS_KEY_NOT_FOUND });
    }

    const accessKey = accessKeys[0];

    // Only granter can revoke
    if (accessKey.userId !== session.user.id) {
      throw new APIError('FORBIDDEN', { message: 'Only granter can revoke' });
    }

    if (accessKey.status === 'revoked') {
      throw new APIError('BAD_REQUEST', { message: TEMPO_ERROR_CODES.ACCESS_KEY_ALREADY_REVOKED });
    }

    const now = new Date().toISOString();
    const revokedKey = (await ctx.context.adapter.update({
      model: 'accessKey',
      where: [{ field: 'id', value: id }],
      update: {
        status: 'revoked',
        revokedAt: now,
        updatedAt: now,
      },
    })) as AccessKeyRecord | null;

    if (!revokedKey) {
      throw new APIError('INTERNAL_SERVER_ERROR', { message: 'Failed to revoke access key' });
    }

    return ctx.json({
      accessKey: serializeAccessKeyRecord(revokedKey),
    } as RevokeAccessKeyResponse);
  }
);
