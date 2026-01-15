/**
 * Tempo Plugin Schema
 *
 * Defines wallet and access key tables for Tempo blockchain integration.
 * Wallets are first-class entities that can sign transactions.
 * Access keys authorize wallets to act on behalf of users.
 */

import type { TempoPluginConfig } from './types';

/**
 * Build schema with additionalFields support
 *
 * Similar to organization plugin, spreads config.schema.TABLE.additionalFields
 * into each table's fields object.
 */
export const getSchema = (options?: TempoPluginConfig) => {
  return {
    /**
     * Passkey table
     *
     * WebAuthn credentials with P-256 public keys.
     * Each passkey derives a Tempo blockchain address.
     */
    passkey: {
      fields: {
        userId: {
          type: 'string' as const,
          required: true,
          references: {
            model: 'user',
            field: 'id',
            onDelete: 'cascade' as const,
          },
        },
        credentialID: {
          type: 'string' as const,
          required: true,
          unique: true,
        },
        publicKey: {
          type: 'string' as const,
          required: true,
        },
        counter: {
          type: 'number' as const,
          required: true,
        },
        deviceType: {
          type: 'string' as const,
          required: false,
        },
        backedUp: {
          type: 'boolean' as const,
          required: false,
        },
        transports: {
          type: 'string' as const,
          required: false,
        },
        name: {
          type: 'string' as const,
          required: false,
        },
        aaguid: {
          type: 'string' as const,
          required: false,
        },
        createdAt: {
          type: 'date' as const,
          required: true,
        },
        ...(options?.schema?.passkey?.additionalFields || {}),
      },
    },

    /**
     * Wallet table
     *
     * Any entity that can sign Tempo transactions:
     * - passkey: User's passkey-derived wallet (P256)
     * - server: Backend wallet (Turnkey, KMS)
     * - external: User's external wallet (MetaMask, etc.)
     */
    wallet: {
      fields: {
        address: {
          type: 'string' as const,
          required: true,
          unique: true,
        },
        keyType: {
          type: 'string' as const,
          required: true,
        },
        walletType: {
          type: 'string' as const,
          required: true,
        },
        passkeyId: {
          type: 'string' as const,
          required: false,
          unique: true,
          references: {
            model: 'passkey',
            field: 'id',
            onDelete: 'cascade' as const,
          },
        },
        userId: {
          type: 'string' as const,
          required: false,
          references: {
            model: 'user',
            field: 'id',
            onDelete: 'set null' as const,
          },
        },
        label: {
          type: 'string' as const,
          required: false,
        },
        createdAt: {
          type: 'date' as const,
          required: true,
        },
        ...(options?.schema?.wallet?.additionalFields || {}),
      },
    },

    /**
     * Access Key table
     *
     * Authorization from user to wallet, with protocol constraints.
     * Tracks the full authorization chain:
     * - userId + rootWalletId → The account being controlled (root key's wallet)
     * - keyWalletId → The wallet authorized to sign for the account (key_id)
     */
    accessKey: {
      fields: {
        userId: {
          type: 'string' as const,
          required: false,
          references: {
            model: 'user',
            field: 'id',
            onDelete: 'cascade' as const,
          },
        },
        rootWalletId: {
          type: 'string' as const,
          required: true,
          references: {
            model: 'wallet',
            field: 'id',
            onDelete: 'restrict' as const,
          },
        },
        keyWalletId: {
          type: 'string' as const,
          required: true,
          references: {
            model: 'wallet',
            field: 'id',
            onDelete: 'restrict' as const,
          },
        },
        chainId: {
          type: 'number' as const,
          required: true,
        },
        expiry: {
          type: 'number' as const,
          required: false,
        },
        limits: {
          type: 'string' as const,
          required: false,
        },
        authorizationSignature: {
          type: 'string' as const,
          required: true,
        },
        authorizationHash: {
          type: 'string' as const,
          required: true,
        },
        status: {
          type: 'string' as const,
          required: true,
        },
        label: {
          type: 'string' as const,
          required: false,
        },
        revokedAt: {
          type: 'string' as const,
          required: false,
        },
        createdAt: {
          type: 'string' as const,
          required: false,
        },
        updatedAt: {
          type: 'string' as const,
          required: false,
        },
        ...(options?.schema?.accessKey?.additionalFields || {}),
      },
    },
  };
};

// Static schema for type inference (without additionalFields)
export const schema = getSchema();
