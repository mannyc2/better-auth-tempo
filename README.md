# better-auth-tempo

[![npm version](https://img.shields.io/npm/v/better-auth-tempo.svg)](https://www.npmjs.com/package/better-auth-tempo)
[![npm downloads](https://img.shields.io/npm/dm/better-auth-tempo.svg)](https://www.npmjs.com/package/better-auth-tempo)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](https://opensource.org/licenses/MIT)

Tempo blockchain plugin for [better-auth](https://github.com/better-auth/better-auth). Enables passkey-based wallets, access key management, and WebAuthn authentication with Tempo address derivation.

## Features

- **Passkey Wallets**: Each passkey automatically derives a Tempo blockchain address (P-256 → keccak256)
- **Access Keys**: Delegated signing authorization with token limits and expiry
- **WebAuthn Integration**: Full ceremony handling for passkey registration and authentication
- **wagmi KeyManager**: Drop-in integration with wagmi's WebAuthn connector

## Installation

```bash
pnpm add better-auth-tempo
```

## Server Setup

```typescript
import { betterAuth } from 'better-auth';
import { tempo } from 'better-auth-tempo';

export const auth = betterAuth({
  // ... your config
  plugins: [
    tempo({
      passkey: {
        rpID: 'example.com',
        rpName: 'My App',
        origin: 'https://example.com',
      },
      serverWallet: {
        address: '0x...', // Backend wallet for access keys
        keyType: 'secp256k1',
      },
      allowedChainIds: [42431], // Tempo Moderato testnet
    }),
  ],
});
```

## Client Setup

```typescript
import { createAuthClient } from 'better-auth/client';
import { tempoClient } from 'better-auth-tempo/client';

export const authClient = createAuthClient({
  baseURL: 'http://localhost:3000',
  plugins: [tempoClient()],
});
```

## Usage

### Register a Passkey Wallet

```typescript
const result = await authClient.registerPasskey({ name: 'My Wallet' });
if (result.data) {
  console.log('Wallet address:', result.data.wallet.address);
}
```

### Authenticate with Passkey

```typescript
const result = await authClient.authenticateWithPasskey();
if (result.data) {
  console.log('Signed in as:', result.data.user.email);
}
```

### Create an Access Key

```typescript
const { data, error } = await authClient.signKeyAuthorization({
  config, // wagmi config
  chainId: 42431,
  keyType: 'secp256k1',
  address: backendWalletAddress,
  limits: [{ token: tokenAddress, amount: BigInt(1000) * BigInt(1_000_000) }],
});

if (data) {
  await authClient.createAccessKey({
    rootWalletId: myWallet.id,
    keyWalletAddress: backendWalletAddress,
    chainId: 42431,
    authorizationSignature: data.signature,
    authorizationHash: data.hash,
  });
}
```

### wagmi KeyManager Integration

```typescript
import { createTempoKeyManager } from 'better-auth-tempo/client';
import { webAuthn } from 'wagmi/connectors';

const keyManager = createTempoKeyManager(authClient);

const config = createConfig({
  connectors: [
    webAuthn({ keyManager }),
  ],
  // ...
});
```

## API Reference

### Server Plugin Options

| Option | Type | Description |
|--------|------|-------------|
| `passkey.rpID` | `string` | Relying Party ID (domain) |
| `passkey.rpName` | `string` | Human-readable app name |
| `passkey.origin` | `string` | Expected origin for WebAuthn |
| `passkey.challengeMaxAge` | `number` | Challenge TTL in seconds (default: 300) |
| `serverWallet.address` | `0x${string}` | Backend wallet address |
| `serverWallet.keyType` | `string` | Key type: secp256k1, p256, webauthn |
| `allowedChainIds` | `number[]` | Allowed chain IDs for access keys |
| `schema` | `object` | Additional fields for tables |

### Client Methods

| Method | Description |
|--------|-------------|
| `registerPasskey()` | Register passkey + create wallet |
| `authenticateWithPasskey()` | Sign in with passkey |
| `listWallets()` | List user's wallets |
| `getServerWallet()` | Get backend wallet for access keys |
| `createAccessKey()` | Create new access key |
| `listAccessKeys()` | List access keys (granted/received) |
| `revokeAccessKey()` | Revoke an access key |
| `signKeyAuthorization()` | Sign authorization with passkey |

## License

MIT
