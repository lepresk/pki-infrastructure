import crypto from 'crypto';
import forge from 'node-forge';

/**
 * Decrypts an AES-256 encrypted PEM private key.
 *
 * node-forge's decryptRsaPrivateKey() silently returns null for AES-256
 * encrypted keys in some Node.js versions. Node.js built-in crypto handles
 * the same format correctly.
 *
 * Workaround flow: forge encryption → Node.js decryption → PKCS#1 re-export → forge key object
 */
export function decryptPrivateKey(
  encryptedPem: string,
  passphrase: string,
): forge.pki.rsa.PrivateKey {
  // Step 1: Node.js crypto decrypts the key correctly
  const keyObject = crypto.createPrivateKey({
    key: encryptedPem,
    format: 'pem',
    passphrase: passphrase,
  });

  // Step 2: export as unencrypted PKCS#1 PEM
  const unencryptedPem = keyObject.export({
    type: 'pkcs1',
    format: 'pem',
  }) as string;

  // Step 3: forge can parse it without problems
  return forge.pki.privateKeyFromPem(unencryptedPem);
}

/**
 * Signs data using an RSA private key with SHA-256.
 * Returns the signature as a base64-encoded string.
 */
export function signData(
  data: string | Buffer,
  privateKey: forge.pki.rsa.PrivateKey,
): string {
  const md = forge.md.sha256.create();
  const content = typeof data === 'string' ? data : data.toString('binary');
  md.update(content, 'utf8');

  const signature = privateKey.sign(md);
  return forge.util.encode64(signature);
}

/**
 * Verifies a base64-encoded RSA signature against the public key
 * embedded in the provided certificate PEM.
 */
export function verifySignature(
  data: string | Buffer,
  signatureBase64: string,
  certificatePem: string,
): boolean {
  try {
    const cert = forge.pki.certificateFromPem(certificatePem);
    const publicKey = cert.publicKey as forge.pki.rsa.PublicKey;

    const md = forge.md.sha256.create();
    const content = typeof data === 'string' ? data : data.toString('binary');
    md.update(content, 'utf8');

    return publicKey.verify(md.digest().bytes(), forge.util.decode64(signatureBase64));
  } catch {
    return false;
  }
}
