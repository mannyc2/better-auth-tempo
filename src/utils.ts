/**
 * Tempo Plugin Utilities
 *
 * Public key conversion and address derivation utilities.
 */

import * as Address from 'ox/Address';
import * as PublicKey from 'ox/PublicKey';
import { decodeCredentialPublicKey, cose, isoBase64URL } from '@simplewebauthn/server/helpers';
import { toHex } from 'viem';

// ============================================================================
// PUBLIC KEY CONVERSION
// ============================================================================
//
// WebAuthn stores public keys as COSE (CBOR-encoded maps with x/y at labels -2/-3).
// Tempo's wire format and address derivation expect raw coordinates (x || y).
//
// We convert at registration to derive tempoAddress: keccak256(x || y)[12:32]
// For SDK requests, we convert on-the-fly since it's fast and avoids storing duplicate data.
//
// Reference: https://docs.tempo.xyz/protocol/transactions/spec-tempo-transaction

/**
 * Convert standard base64 to base64url encoding.
 * better-auth stores publicKey in standard base64, but isoBase64URL expects base64url.
 */
function base64ToBase64url(base64: string): string {
  return base64.replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

/**
 * Extract raw P-256 coordinates from a base64-encoded COSE public key.
 * Returns 64-byte hex string (x || y) for Tempo SDK consumption.
 */
export function coseKeyToHex(publicKeyBase64: string): `0x${string}` {
  const coseBytes = isoBase64URL.toBuffer(base64ToBase64url(publicKeyBase64), 'base64url');
  const coseKey = decodeCredentialPublicKey(coseBytes);

  if (!cose.isCOSEPublicKeyEC2(coseKey)) {
    throw new Error('Expected EC2 COSE key for P-256 passkey');
  }

  const x = coseKey.get(cose.COSEKEYS.x);
  const y = coseKey.get(cose.COSEKEYS.y);

  if (!(x instanceof Uint8Array) || !(y instanceof Uint8Array)) {
    throw new Error('Missing x or y coordinate in COSE key');
  }
  if (x.length !== 32 || y.length !== 32) {
    throw new Error(`Invalid P-256 coordinates: x=${x.length}, y=${y.length}`);
  }

  const combined = new Uint8Array(64);
  combined.set(x, 0);
  combined.set(y, 32);
  return toHex(combined) as `0x${string}`;
}

/**
 * Derive Tempo address from a base64-encoded COSE public key.
 * Uses Tempo's address derivation: keccak256(x || y)[12:32]
 */
export function deriveTempoAddress(publicKeyBase64: string): `0x${string}` {
  const publicKeyHex = coseKeyToHex(publicKeyBase64);
  const publicKey = PublicKey.fromHex(publicKeyHex);
  return Address.fromPublicKey(publicKey);
}

/**
 * Check if a public key string is hex format (from SDK) or base64 COSE (from @simplewebauthn).
 */
export function isHexPublicKey(publicKey: string): publicKey is `0x${string}` {
  return publicKey.startsWith('0x');
}

/**
 * Get hex public key from either format.
 * Handles both SDK hex format and @simplewebauthn COSE base64 format.
 */
export function getPublicKeyHex(publicKey: string): `0x${string}` {
  if (isHexPublicKey(publicKey)) {
    return publicKey;
  }
  return coseKeyToHex(publicKey);
}

/**
 * Convert hex public key (0x04 + x + y or just x + y) to COSE base64.
 * Used for SDK registration path to store in consistent format.
 */
export function hexToCose(publicKeyHex: `0x${string}`): string {
  // Remove 0x prefix
  let hex = publicKeyHex.slice(2);

  // Remove 04 prefix if present (uncompressed point indicator)
  if (hex.length === 130 && hex.startsWith('04')) {
    hex = hex.slice(2);
  }

  if (hex.length !== 128) {
    throw new Error(
      `Invalid public key length: expected 128 hex chars (64 bytes), got ${hex.length}`
    );
  }

  const x = hexToBytes(hex.slice(0, 64));
  const y = hexToBytes(hex.slice(64, 128));

  // Build COSE EC2 P-256 key manually
  // A4 = map(4)
  // 01 02 = kty: EC2
  // 20 01 = crv: P-256 (-1: 1)
  // 21 58 20 = x: bstr(32) (-2: ...)
  // 22 58 20 = y: bstr(32) (-3: ...)
  const coseBytes = new Uint8Array(4 + 32 + 3 + 32 + 3); // header + x + y with prefixes

  let offset = 0;
  coseBytes[offset++] = 0xa4; // map(4)
  coseBytes[offset++] = 0x01; // key: 1 (kty)
  coseBytes[offset++] = 0x02; // value: 2 (EC2)
  coseBytes[offset++] = 0x20; // key: -1 (crv)
  coseBytes[offset++] = 0x01; // value: 1 (P-256)
  coseBytes[offset++] = 0x21; // key: -2 (x)
  coseBytes[offset++] = 0x58; // bstr, 1-byte length follows
  coseBytes[offset++] = 0x20; // length: 32
  coseBytes.set(x, offset);
  offset += 32;
  coseBytes[offset++] = 0x22; // key: -3 (y)
  coseBytes[offset++] = 0x58; // bstr, 1-byte length follows
  coseBytes[offset++] = 0x20; // length: 32
  coseBytes.set(y, offset);

  // Standard base64 to match better-auth storage
  return btoa(String.fromCharCode(...coseBytes));
}

function hexToBytes(hex: string): Uint8Array {
  const bytes = new Uint8Array(hex.length / 2);
  for (let i = 0; i < bytes.length; i++) {
    bytes[i] = Number.parseInt(hex.slice(i * 2, i * 2 + 2), 16);
  }
  return bytes;
}

/**
 * Derive Tempo address from a hex public key (from SDK).
 * Uses Tempo's address derivation: keccak256(x || y)[12:32]
 */
export function deriveTempoAddressFromHex(publicKeyHex: `0x${string}`): `0x${string}` {
  const publicKey = PublicKey.fromHex(publicKeyHex);
  return Address.fromPublicKey(publicKey);
}
