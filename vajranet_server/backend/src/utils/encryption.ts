import { createCipheriv, createDecipheriv, randomBytes } from 'crypto';
import { getLogger } from './logger';

const logger = getLogger('utils.encryption');

const ALGORITHM = 'aes-256-gcm';
const IV_LENGTH = 12;
const KEY_LENGTH = 32;

// This module is called from many controllers (Nessus/OpenVAS/Burpsuite/AI
// provider/domain-reputation credential storage), not all of which wrap
// encrypt/decrypt failures with their own logging. Logging the specific
// reason here — not just letting the thrown Error propagate — is the only
// way a config-key problem ("env var missing/wrong length") is
// distinguishable in logs from a data problem ("wrong key or tampered
// ciphertext", surfaced below in decrypt()), which would otherwise look
// identical to whoever's catch block only logs a generic message.
function getEncryptionKey(): Buffer {
  const keyHex = process.env.NESSUS_ENCRYPTION_KEY;
  if (!keyHex) {
    logger.error('NESSUS_ENCRYPTION_KEY environment variable is not set');
    throw new Error(
      'NESSUS_ENCRYPTION_KEY environment variable is not set. ' +
      'Generate a 32-byte hex key: node -e "console.log(require(\'crypto\').randomBytes(32).toString(\'hex\'))"',
    );
  }
  const key = Buffer.from(keyHex, 'hex');
  if (key.length !== KEY_LENGTH) {
    logger.error({ expectedBytes: KEY_LENGTH, actualBytes: key.length }, 'NESSUS_ENCRYPTION_KEY is not the expected length');
    throw new Error(`NESSUS_ENCRYPTION_KEY must be exactly ${KEY_LENGTH} bytes (${KEY_LENGTH * 2} hex characters). Got ${key.length} bytes.`);
  }
  return key;
}

export interface EncryptedData {
  ciphertext: string;
  iv: string;
  authTag: string;
}

export function encrypt(plaintext: string): EncryptedData {
  const key = getEncryptionKey();
  const iv = randomBytes(IV_LENGTH);
  const cipher = createCipheriv(ALGORITHM, key, iv);

  let encrypted = cipher.update(plaintext, 'utf8', 'hex');
  encrypted += cipher.final('hex');
  const authTag = cipher.getAuthTag();

  return {
    ciphertext: encrypted,
    iv: iv.toString('hex'),
    authTag: authTag.toString('hex'),
  };
}

export function decrypt(ciphertext: string, iv: string, authTag: string): string {
  const key = getEncryptionKey();
  try {
    const decipher = createDecipheriv(ALGORITHM, key, Buffer.from(iv, 'hex'));
    decipher.setAuthTag(Buffer.from(authTag, 'hex'));

    let decrypted = decipher.update(ciphertext, 'hex', 'utf8');
    decrypted += decipher.final('utf8');

    return decrypted;
  } catch (err) {
    // GCM auth-tag verification failure (wrong key, or the ciphertext/iv/tag
    // was tampered or corrupted) throws here with a generic native crypto
    // message ("Unsupported state or unable to authenticate data") that
    // carries no identifying detail on its own.
    logger.error({ err }, 'Decryption failed — ciphertext/iv/authTag invalid, corrupted, or encrypted with a different key');
    throw err;
  }
}
