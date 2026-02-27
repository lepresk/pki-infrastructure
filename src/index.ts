import {
  generateRootCA,
  generateIntermediateCA,
  generateSigningCertificate,
  verifyCertificateChain,
} from './pki.js';
import { decryptPrivateKey, signData, verifySignature } from './crypto.js';
import {
  saveRootCA,
  saveIntermediateCA,
  saveSigningCertificate,
} from './storage.js';

async function main() {
  // Use an env variable in production — never hardcode passphrases
  const passphrase = process.env.PKI_PASSPHRASE ?? 'min-12-char-passphrase';

  // ── Step 1: Root CA ────────────────────────────────────────────────────────
  console.log('Generating Root CA (4096-bit, this may take a moment)…');
  const rootCA = await generateRootCA(passphrase);
  await saveRootCA(rootCA, 'pki/root-ca');
  console.log('✓ Root CA created → pki/root-ca/');

  // ── Step 2: Intermediate CA ────────────────────────────────────────────────
  console.log('Generating Intermediate CA…');
  const intermediateCA = await generateIntermediateCA(rootCA, passphrase, {
    commonName: 'My Signing CA',
    organization: 'My Org',
    country: 'FR',
    validityYears: 5,
  });
  await saveIntermediateCA(intermediateCA, 'pki/intermediate-ca');
  console.log('✓ Intermediate CA created → pki/intermediate-ca/');

  // ── Step 3: Leaf signing certificate ──────────────────────────────────────
  console.log('Issuing signing certificate…');
  const accountantCert = await generateSigningCertificate(intermediateCA, passphrase, {
    commonName: 'Cabinet Dupont & Associés',
    organization: 'Cabinet Dupont',
    country: 'FR',
    validityDays: 730,
  });
  await saveSigningCertificate(accountantCert, 'pki/certs/cabinet-dupont');
  console.log('✓ Signing certificate issued → pki/certs/cabinet-dupont/');

  // ── Step 4: Certificate chain verification ─────────────────────────────────
  const chainResult = verifyCertificateChain(
    accountantCert.certificate,
    intermediateCA.certificate,
    rootCA.certificate,
  );
  console.log(`\nChain verification: ${chainResult.valid ? '✓ VALID' : `✗ INVALID — ${chainResult.error}`}`);

  // ── Step 5: Document signing ───────────────────────────────────────────────
  const document = 'Tax declaration 2024-Q4';
  const privateKey = decryptPrivateKey(accountantCert.privateKey, passphrase);

  const signature = signData(document, privateKey);
  console.log(`\nDocument signed.`);
  console.log(`Signature (base64): ${signature.slice(0, 60)}…`);

  // Verify authentic document
  const isValid = verifySignature(document, signature, accountantCert.certificate);
  console.log(`\nSignature verification (original):  ${isValid ? '✓ VALID' : '✗ INVALID'}`);

  // Verify tampered document
  const isTamperedValid = verifySignature(
    document + ' (modified)',
    signature,
    accountantCert.certificate,
  );
  console.log(`Signature verification (tampered):  ${isTamperedValid ? '✓ VALID' : '✗ INVALID'}`);
}

main().catch((err) => {
  console.error('Fatal error:', err);
  process.exit(1);
});
