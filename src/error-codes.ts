/**
 * Tempo Plugin Error Codes
 *
 * Plain string error codes for $ERROR_CODES export.
 * Used with APIError: throw new APIError('STATUS', { message: TEMPO_ERROR_CODES.X })
 */
export const TEMPO_ERROR_CODES = {
  INVALID_REQUEST: 'Invalid request body',
  MISSING_REQUIRED_FIELDS: 'keyId, chainId, keyType, and signature are required',
  INVALID_CHAIN_ID: 'Invalid chain ID',
  INVALID_BACKEND_KEY: 'Invalid backend key ID',
  INVALID_LIMIT_AMOUNT: 'All limit amounts must be strings (wei values)',
  ACCESS_KEY_EXISTS:
    'An active Access Key already exists for this account. Revoke it first to create a new one.',
  ACCESS_KEY_NOT_FOUND: 'Access Key not found',
  ACCESS_DENIED: 'Access denied',
  ACCESS_KEY_ALREADY_REVOKED: 'Access Key already revoked',
  ACCESS_KEY_ID_REQUIRED: 'Access Key ID required',
  KEY_NOT_FOUND: 'Key not found',
  MISSING_CREDENTIAL_ID: 'Missing credentialId',
} as const;
