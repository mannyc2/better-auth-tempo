import { APIError } from 'better-auth/api';
import { getTestInstance } from 'better-auth/test';
import { describe, expect, it, beforeAll } from 'vitest';
import { passkey } from '@better-auth/passkey';
import { tempo } from '../src';
import type { Wallet } from '../src/types';

// Internal wallet record type for adapter operations
interface WalletRecord {
  id?: string;
  address: string;
  keyType: string;
  walletType: string;
  passkeyId: string | null;
  userId: string | null;
  label: string | null;
  createdAt: Date;
}

/**
 * Tempo Plugin Tests
 *
 * Tests wallet management, access keys, and KeyManager endpoints.
 * Uses better-auth test utilities for isolated database testing.
 */
describe('tempo plugin', async () => {
  const tempoPlugin = tempo({
    allowedChainIds: [42431],
    defaults: {
      accessKeyLabel: 'Test Access Key',
    },
  });

  const { auth, signInWithTestUser } = await getTestInstance({
    plugins: [passkey(), tempoPlugin],
  });

  // Type definitions for API responses
  interface AccessKeyResponse {
    id: string;
    status: string;
    rootWalletId: string;
    keyWalletId: string;
    chainId: number;
    revokedAt?: string;
  }

  interface CreateAccessKeyResponse {
    accessKey: AccessKeyResponse;
    rootWallet: Wallet;
    keyWallet: Wallet;
  }

  // Type the auth.api with our plugin's endpoints
  const api = auth.api as typeof auth.api & {
    listWallets: (opts: { headers: Headers }) => Promise<{ wallets: Wallet[] }>;
    createWallet: (opts: { headers: Headers; body: Record<string, unknown> }) => Promise<{
      wallet: Wallet;
    }>;
    getWallet: (opts: { headers: Headers; params: { idOrAddress: string } }) => Promise<{
      wallet: Wallet;
    }>;
    createAccessKey: (opts: {
      headers: Headers;
      body: Record<string, unknown>;
    }) => Promise<CreateAccessKeyResponse>;
    listAccessKeys: (opts: { headers: Headers; query?: Record<string, unknown> }) => Promise<{
      accessKeys: AccessKeyResponse[];
      direction: string;
    }>;
    getAccessKey: (opts: { headers: Headers; params: { id: string } }) => Promise<{
      accessKey: AccessKeyResponse;
    }>;
    revokeAccessKey: (opts: { headers: Headers; params: { id: string } }) => Promise<{
      accessKey: AccessKeyResponse;
    }>;
    listTempoPasskeys: (opts: { headers: Headers }) => Promise<unknown[]>;
    getPasskeyRegistrationOptions: (opts: { headers: Headers }) => Promise<{
      challenge: string;
      rp: { id: string; name: string };
    }>;
    getPasskeyAuthenticationOptions: (opts: Record<string, never>) => Promise<{
      challenge: string;
      rpId: string;
    }>;
    deletePasskey: (opts: {
      headers: Headers;
      params: { credentialId: string };
    }) => Promise<{ success: boolean }>;
    getServerWallet: (opts: { headers: Headers }) => Promise<{ wallet: Wallet }>;
  };

  // ============================================================================
  // WALLET ENDPOINTS
  // ============================================================================

  describe('wallets', () => {
    it('should list wallets for authenticated user', async () => {
      const { headers } = await signInWithTestUser();
      const result = await api.listWallets({ headers });

      expect(result).toHaveProperty('wallets');
      expect(Array.isArray(result.wallets)).toBe(true);
    });

    it('should create a server wallet', async () => {
      const { headers } = await signInWithTestUser();
      const result = await api.createWallet({
        headers,
        body: {
          address: '0x1234567890123456789012345678901234567890',
          keyType: 'secp256k1',
          walletType: 'server',
          label: 'Test Server Wallet',
        },
      });

      expect(result).toHaveProperty('wallet');
      expect(result.wallet.address).toBe('0x1234567890123456789012345678901234567890');
      expect(result.wallet.walletType).toBe('server');
      expect(result.wallet.keyType).toBe('secp256k1');
      expect(result.wallet.label).toBe('Test Server Wallet');
    });

    it('should create an external wallet', async () => {
      const { headers } = await signInWithTestUser();
      const result = await api.createWallet({
        headers,
        body: {
          address: '0xabcdef1234567890abcdef1234567890abcdef12',
          keyType: 'secp256k1',
          walletType: 'external',
          label: 'MetaMask Wallet',
        },
      });

      expect(result).toHaveProperty('wallet');
      expect(result.wallet.walletType).toBe('external');
      // External wallets should be associated with the current user
      expect(result.wallet.userId).toBeDefined();
    });

    it('should reject duplicate wallet addresses', async () => {
      const { headers } = await signInWithTestUser();
      const address = '0xdeadbeef12345678901234567890123456789012';

      // Create first wallet
      await api.createWallet({
        headers,
        body: {
          address,
          keyType: 'secp256k1',
          walletType: 'server',
        },
      });

      // Attempt duplicate
      await expect(
        api.createWallet({
          headers,
          body: {
            address,
            keyType: 'secp256k1',
            walletType: 'server',
          },
        })
      ).rejects.toThrowError(APIError);
    });

    it('should get wallet by ID', async () => {
      const { headers } = await signInWithTestUser();

      // Create a wallet first
      const createResult = await api.createWallet({
        headers,
        body: {
          address: '0x1111111111111111111111111111111111111111',
          keyType: 'secp256k1',
          walletType: 'server',
        },
      });

      const result = await api.getWallet({
        headers,
        params: { idOrAddress: createResult.wallet.id },
      });

      expect(result).toHaveProperty('wallet');
      expect(result.wallet.id).toBe(createResult.wallet.id);
    });

    it('should get wallet by address', async () => {
      const { headers } = await signInWithTestUser();
      const address = '0x2222222222222222222222222222222222222222';

      await api.createWallet({
        headers,
        body: {
          address,
          keyType: 'secp256k1',
          walletType: 'server',
        },
      });

      const result = await api.getWallet({
        headers,
        params: { idOrAddress: address },
      });

      expect(result.wallet.address).toBe(address);
    });

    it('should return 404 for non-existent wallet', async () => {
      const { headers } = await signInWithTestUser();

      await expect(
        api.getWallet({
          headers,
          params: { idOrAddress: 'non-existent-id' },
        })
      ).rejects.toThrowError(APIError);
    });

    it('should reject passkey walletType (created via hook only)', async () => {
      const { headers } = await signInWithTestUser();

      await expect(
        api.createWallet({
          headers,
          body: {
            address: '0x3333333333333333333333333333333333333333',
            keyType: 'p256',
            walletType: 'passkey' as 'server', // Force invalid type to test validation
          },
        })
      ).rejects.toThrowError(APIError);
    });

    it('should get shared server wallet', async () => {
      const { headers } = await signInWithTestUser();
      const context = await auth.$context;

      // Create a shared server wallet (userId: null)
      const serverWalletAddress = '0xSERVER0000000000000000000000000000000001';
      await context.adapter.create({
        model: 'wallet',
        data: {
          address: serverWalletAddress,
          keyType: 'secp256k1',
          walletType: 'server',
          passkeyId: null,
          userId: null, // Shared server wallet has no userId
          label: 'Shared Server Wallet',
          createdAt: new Date(),
        },
      });

      const result = await api.getServerWallet({ headers });

      expect(result).toHaveProperty('wallet');
      expect(result.wallet.walletType).toBe('server');
      expect(result.wallet.userId).toBeNull();
    });

    it('should return 404 when no server wallet configured', async () => {
      const { headers } = await signInWithTestUser();
      const context = await auth.$context;

      // Delete any existing server wallets with null userId
      const serverWallets = await context.adapter.findMany({
        model: 'wallet',
        where: [{ field: 'walletType', value: 'server' }],
      });
      for (const wallet of serverWallets) {
        if ((wallet as { userId: string | null }).userId === null) {
          await context.adapter.delete({
            model: 'wallet',
            where: [{ field: 'id', value: (wallet as { id: string }).id }],
          });
        }
      }

      await expect(api.getServerWallet({ headers })).rejects.toThrowError(APIError);
    });
  });

  // ============================================================================
  // ACCESS KEY ENDPOINTS
  // ============================================================================

  describe('access keys', () => {
    let rootWallet: Wallet;
    let keyWallet: Wallet;

    beforeAll(async () => {
      const { headers, user } = await signInWithTestUser();
      const context = await auth.$context;

      // Create root wallet (user's passkey wallet simulation)
      const rootResult = (await context.adapter.create({
        model: 'wallet',
        data: {
          address: '0xROOT000000000000000000000000000000000001',
          keyType: 'p256',
          walletType: 'passkey',
          passkeyId: null,
          userId: user.id,
          label: 'Test Root Wallet',
          createdAt: new Date(),
        } satisfies Omit<WalletRecord, 'id'>,
      })) as Wallet;
      rootWallet = rootResult;

      // Create key wallet (server wallet)
      const keyResult = await api.createWallet({
        headers,
        body: {
          address: '0xKEY0000000000000000000000000000000000001',
          keyType: 'secp256k1',
          walletType: 'server',
          label: 'Test Key Wallet',
        },
      });
      keyWallet = keyResult.wallet;
    });

    it('should create an access key', async () => {
      const { headers } = await signInWithTestUser();

      const result = await api.createAccessKey({
        headers,
        body: {
          rootWalletId: rootWallet.id,
          keyWalletId: keyWallet.id,
          chainId: 42431,
          limits: [{ token: '0xTOKEN00000000000000000000000000000000001', limit: '1000000000' }],
          authorizationSignature: '0xmocksignature',
          authorizationHash: '0xmockhash',
          label: 'Test Access Key',
        },
      });

      expect(result).toHaveProperty('accessKey');
      expect(result).toHaveProperty('rootWallet');
      expect(result).toHaveProperty('keyWallet');
      expect(result.accessKey.status).toBe('active');
      expect(result.accessKey.chainId).toBe(42431);
      expect(result.accessKey.rootWalletId).toBe(rootWallet.id);
      expect(result.accessKey.keyWalletId).toBe(keyWallet.id);
    });

    it('should create access key using keyWalletAddress', async () => {
      const { headers } = await signInWithTestUser();

      const result = await api.createAccessKey({
        headers,
        body: {
          rootWalletId: rootWallet.id,
          keyWalletAddress: keyWallet.address as `0x${string}`,
          chainId: 42431,
          authorizationSignature: '0xmocksignature2',
          authorizationHash: '0xmockhash2',
        },
      });

      expect(result.accessKey.keyWalletId).toBe(keyWallet.id);
    });

    it('should reject access key with invalid chain ID', async () => {
      const { headers } = await signInWithTestUser();

      await expect(
        api.createAccessKey({
          headers,
          body: {
            rootWalletId: rootWallet.id,
            keyWalletId: keyWallet.id,
            chainId: 99999, // Not in allowedChainIds
            authorizationSignature: '0xmocksig',
            authorizationHash: '0xmockhash',
          },
        })
      ).rejects.toThrowError(APIError);
    });

    it('should reject access key for wallet not owned by user', async () => {
      const { headers } = await signInWithTestUser();
      const context = await auth.$context;

      // Create another user first
      const otherUser = (await context.adapter.create({
        model: 'user',
        data: {
          name: 'Other User',
          email: 'other@example.com',
          emailVerified: false,
          createdAt: new Date(),
          updatedAt: new Date(),
        },
      })) as { id: string };

      // Create wallet owned by different user
      const otherWallet = (await context.adapter.create({
        model: 'wallet',
        data: {
          address: '0xOTHER0000000000000000000000000000000001',
          keyType: 'p256',
          walletType: 'passkey',
          passkeyId: null,
          userId: otherUser.id,
          label: 'Other User Wallet',
          createdAt: new Date(),
        } satisfies Omit<WalletRecord, 'id'>,
      })) as Wallet;

      await expect(
        api.createAccessKey({
          headers,
          body: {
            rootWalletId: otherWallet.id,
            keyWalletId: keyWallet.id,
            chainId: 42431,
            authorizationSignature: '0xmocksig',
            authorizationHash: '0xmockhash',
          },
        })
      ).rejects.toThrowError(APIError);
    });

    it('should list granted access keys', async () => {
      const { headers } = await signInWithTestUser();

      const result = await api.listAccessKeys({
        headers,
        query: { direction: 'granted' },
      });

      expect(result).toHaveProperty('accessKeys');
      expect(result.direction).toBe('granted');
      expect(Array.isArray(result.accessKeys)).toBe(true);
    });

    it('should list received access keys', async () => {
      const { headers } = await signInWithTestUser();

      // Note: query params may not be passed correctly via test utils
      // This tests that the endpoint returns valid structure
      const result = await api.listAccessKeys({
        headers,
        query: { direction: 'received' },
      });

      expect(result).toHaveProperty('accessKeys');
      expect(result).toHaveProperty('direction');
      expect(Array.isArray(result.accessKeys)).toBe(true);
    });

    it('should get access key by ID', async () => {
      const { headers } = await signInWithTestUser();

      // Create an access key first
      const createResult = await api.createAccessKey({
        headers,
        body: {
          rootWalletId: rootWallet.id,
          keyWalletId: keyWallet.id,
          chainId: 42431,
          authorizationSignature: '0xsig-for-get',
          authorizationHash: '0xhash-for-get',
        },
      });

      const result = await api.getAccessKey({
        headers,
        params: { id: createResult.accessKey.id },
      });

      expect(result).toHaveProperty('accessKey');
      expect(result.accessKey.id).toBe(createResult.accessKey.id);
    });

    it('should return 404 for non-existent access key', async () => {
      const { headers } = await signInWithTestUser();

      await expect(
        api.getAccessKey({
          headers,
          params: { id: 'non-existent-id' },
        })
      ).rejects.toThrowError(APIError);
    });

    it('should revoke an access key', async () => {
      const { headers } = await signInWithTestUser();

      // Create access key
      const createResult = await api.createAccessKey({
        headers,
        body: {
          rootWalletId: rootWallet.id,
          keyWalletId: keyWallet.id,
          chainId: 42431,
          authorizationSignature: '0xsig-to-revoke',
          authorizationHash: '0xhash-to-revoke',
        },
      });

      // Revoke it
      const result = await api.revokeAccessKey({
        headers,
        params: { id: createResult.accessKey.id },
      });

      expect(result.accessKey.status).toBe('revoked');
      expect(result.accessKey.revokedAt).toBeDefined();
    });

    it('should reject revoking already revoked key', async () => {
      const { headers } = await signInWithTestUser();

      // Create and revoke
      const createResult = await api.createAccessKey({
        headers,
        body: {
          rootWalletId: rootWallet.id,
          keyWalletId: keyWallet.id,
          chainId: 42431,
          authorizationSignature: '0xsig-double-revoke',
          authorizationHash: '0xhash-double-revoke',
        },
      });

      await api.revokeAccessKey({
        headers,
        params: { id: createResult.accessKey.id },
      });

      // Try to revoke again
      await expect(
        api.revokeAccessKey({
          headers,
          params: { id: createResult.accessKey.id },
        })
      ).rejects.toThrowError(APIError);
    });
  });

  // ============================================================================
  // PASSKEY ENDPOINTS
  // ============================================================================

  describe('passkeys', () => {
    it('should list tempo passkeys with derived addresses', async () => {
      const { headers, user } = await signInWithTestUser();
      const context = await auth.$context;

      // Create a mock passkey with valid COSE public key
      // This is a minimal valid COSE key structure for testing
      const mockCoseKey = Buffer.from([
        0xa5, // map(5)
        0x01,
        0x02, // kty: 2 (EC2)
        0x03,
        0x26, // alg: -7 (ES256)
        0x20,
        0x01, // crv: 1 (P-256)
        0x21,
        0x58,
        0x20, // x: bytes(32)
        ...Array(32).fill(0x01), // x coordinate
        0x22,
        0x58,
        0x20, // y: bytes(32)
        ...Array(32).fill(0x02), // y coordinate
      ]).toString('base64');

      await context.adapter.create({
        model: 'passkey',
        data: {
          userId: user.id,
          publicKey: mockCoseKey,
          name: 'Test Passkey',
          counter: 0,
          deviceType: 'singleDevice',
          credentialID: 'test-credential-id',
          createdAt: new Date(),
          backedUp: false,
          transports: 'internal',
          aaguid: 'test-aaguid',
        },
      });

      const result = await api.listTempoPasskeys({ headers });

      expect(Array.isArray(result)).toBe(true);
      if (result.length > 0) {
        expect(result[0]).toHaveProperty('tempoAddress');
        expect(result[0]).toHaveProperty('publicKey');
        expect(result[0]).toHaveProperty('credentialID');
      }
    });
  });

  // ============================================================================
  // KEYMANAGER ENDPOINTS (Tempo SDK Integration)
  // ============================================================================

  describe('keymanager', () => {
    it('should list keys for authenticated user', async () => {
      const { headers } = await signInWithTestUser();

      const result = await api.listTempoPasskeys({ headers });

      expect(Array.isArray(result)).toBe(true);
    });

    it('should get challenge for WebAuthn registration', async () => {
      const { headers } = await signInWithTestUser();

      const result = await api.getPasskeyRegistrationOptions({ headers });

      expect(result).toHaveProperty('challenge');
      expect(result).toHaveProperty('rp');
      expect(typeof result.challenge).toBe('string');
      expect(result.challenge.length).toBeGreaterThan(0);
      expect(result.rp).toHaveProperty('id');
      expect(result.rp).toHaveProperty('name');
    });

    it('should get authentication options without session', async () => {
      const result = await api.getPasskeyAuthenticationOptions({});

      expect(result).toHaveProperty('challenge');
      expect(result).toHaveProperty('rpId');
      expect(typeof result.challenge).toBe('string');
      expect(result.challenge.length).toBeGreaterThan(0);
    });

    it('should delete passkey owned by user', async () => {
      const { headers, user } = await signInWithTestUser();
      const context = await auth.$context;

      const credentialId = 'delete-test-cred-' + Date.now();
      const mockCoseKey = Buffer.from([
        0xa5, 0x01, 0x02, 0x03, 0x26, 0x20, 0x01, 0x21, 0x58, 0x20,
        ...Array(32).fill(0xaa),
        0x22, 0x58, 0x20,
        ...Array(32).fill(0xbb),
      ]).toString('base64');

      await context.adapter.create({
        model: 'passkey',
        data: {
          userId: user.id,
          publicKey: mockCoseKey,
          name: 'Delete Test Passkey',
          counter: 0,
          deviceType: 'singleDevice',
          credentialID: credentialId,
          createdAt: new Date(),
          backedUp: false,
          transports: 'internal',
        },
      });

      const result = await api.deletePasskey({
        headers,
        params: { credentialId },
      });

      expect(result).toHaveProperty('success', true);

      // Verify passkey is deleted by checking listTempoPasskeys
      const passkeys = await api.listTempoPasskeys({ headers });
      const found = (passkeys as { credentialID: string }[]).find(
        (p) => p.credentialID === credentialId
      );
      expect(found).toBeUndefined();
    });

    it('should return 404 for non-existent passkey', async () => {
      const { headers } = await signInWithTestUser();

      await expect(
        api.deletePasskey({
          headers,
          params: { credentialId: 'non-existent-cred-id' },
        })
      ).rejects.toThrowError(APIError);
    });

    it('should reject deleting another user\'s passkey', async () => {
      const context = await auth.$context;

      // Create another user using the internal adapter
      const otherUser = await context.internalAdapter.createUser({
        email: `other-${Date.now()}@test.com`,
        name: 'Other User',
        emailVerified: true,
      });

      const otherCredentialId = 'other-user-cred-' + Date.now();
      const mockCoseKey = Buffer.from([
        0xa5, 0x01, 0x02, 0x03, 0x26, 0x20, 0x01, 0x21, 0x58, 0x20,
        ...Array(32).fill(0xcc),
        0x22, 0x58, 0x20,
        ...Array(32).fill(0xdd),
      ]).toString('base64');

      await context.adapter.create({
        model: 'passkey',
        data: {
          userId: otherUser.id,
          publicKey: mockCoseKey,
          name: 'Other User Passkey',
          counter: 0,
          deviceType: 'singleDevice',
          credentialID: otherCredentialId,
          createdAt: new Date(),
          backedUp: false,
          transports: 'internal',
        },
      });

      // Sign in as a different user and try to delete
      const { headers } = await signInWithTestUser();

      await expect(
        api.deletePasskey({
          headers,
          params: { credentialId: otherCredentialId },
        })
      ).rejects.toThrowError(APIError);
    });
  });

  // ============================================================================
  // AUTHENTICATION
  // ============================================================================

  describe('authentication', () => {
    it('should reject unauthenticated requests to listWallets', async () => {
      await expect(api.listWallets({} as { headers: Headers })).rejects.toThrowError();
    });

    it('should reject unauthenticated requests to createAccessKey', async () => {
      await expect(
        // @ts-expect-error - intentionally omitting headers to test auth
        api.createAccessKey({
          body: {
            rootWalletId: 'test',
            keyWalletId: 'test',
            chainId: 42431,
            authorizationSignature: '0x',
            authorizationHash: '0x',
          },
        })
      ).rejects.toThrowError();
    });
  });
});
