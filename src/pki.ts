import crypto from 'crypto';
import forge from 'node-forge';
import { decryptPrivateKey } from './crypto.js';
import type {
  CACertificate,
  CertificateChainVerificationResult,
  IntermediateCACertificate,
  IntermediateCAOptions,
  SigningCertificate,
  SigningCertificateOptions,
} from './types.js';

/**
 * Generates a self-signed Root CA certificate with a 4096-bit RSA key.
 * The private key is AES-256 encrypted with the provided passphrase.
 * Valid for 10 years.
 */
export async function generateRootCA(passphrase: string): Promise<CACertificate> {
  const keys = forge.pki.rsa.generateKeyPair({ bits: 4096, workers: -1 });

  const cert = forge.pki.createCertificate();
  cert.publicKey = keys.publicKey;
  cert.serialNumber = crypto.randomBytes(16).toString('hex');

  const now = new Date();
  cert.validity.notBefore = new Date(now.getTime() - 5 * 60 * 1000); // 5 min buffer for clock skew
  cert.validity.notAfter = new Date();
  cert.validity.notAfter.setFullYear(now.getFullYear() + 10);

  const attrs = [
    { name: 'commonName', value: 'My Root CA' },
    { name: 'organizationName', value: 'My Org' },
    { name: 'countryName', value: 'FR' },
  ];

  cert.setSubject(attrs);
  cert.setIssuer(attrs);

  cert.setExtensions([
    {
      name: 'basicConstraints',
      cA: true,
      critical: true,
    },
    {
      name: 'keyUsage',
      keyCertSign: true,
      cRLSign: true,
      critical: true,
    },
    {
      name: 'subjectKeyIdentifier',
    },
  ]);

  cert.sign(keys.privateKey, forge.md.sha256.create());

  const privateKeyPem = forge.pki.encryptRsaPrivateKey(keys.privateKey, passphrase, {
    algorithm: 'aes256',
  });

  return {
    certificate: forge.pki.certificateToPem(cert),
    privateKey: privateKeyPem,
    publicKey: forge.pki.publicKeyToPem(keys.publicKey),
  };
}

/**
 * Generates an Intermediate CA certificate signed by the Root CA.
 * Uses a 2048-bit RSA key. pathlenConstraint=0 prevents further intermediate CAs.
 */
export async function generateIntermediateCA(
  rootCA: CACertificate,
  rootPassphrase: string,
  options: IntermediateCAOptions,
): Promise<IntermediateCACertificate> {
  const { commonName, organization = '', country = '', validityYears = 5 } = options;

  const rootPrivateKey = decryptPrivateKey(rootCA.privateKey, rootPassphrase);

  const keys = forge.pki.rsa.generateKeyPair({ bits: 2048, workers: -1 });
  const cert = forge.pki.createCertificate();

  cert.publicKey = keys.publicKey;
  cert.serialNumber = crypto.randomBytes(16).toString('hex');

  const now = new Date();
  cert.validity.notBefore = new Date(now.getTime() - 5 * 60 * 1000);
  cert.validity.notAfter = new Date();
  cert.validity.notAfter.setFullYear(now.getFullYear() + validityYears);

  const subjectAttrs: forge.pki.CertificateField[] = [{ name: 'commonName', value: commonName }];
  if (organization) subjectAttrs.push({ name: 'organizationName', value: organization });
  if (country) subjectAttrs.push({ name: 'countryName', value: country });

  cert.setSubject(subjectAttrs);

  const rootCACert = forge.pki.certificateFromPem(rootCA.certificate);
  cert.setIssuer(rootCACert.subject.attributes);

  cert.setExtensions([
    {
      name: 'basicConstraints',
      cA: true,
      pathlenConstraint: 0,
      critical: true,
    },
    {
      name: 'keyUsage',
      keyCertSign: true,
      cRLSign: true,
      critical: true,
    },
    {
      name: 'authorityKeyIdentifier',
      keyIdentifier: true,
      authorityCertIssuer: true,
    },
    { name: 'subjectKeyIdentifier' },
  ]);

  cert.sign(rootPrivateKey, forge.md.sha256.create());

  const privateKeyPem = forge.pki.encryptRsaPrivateKey(keys.privateKey, rootPassphrase, {
    algorithm: 'aes256',
  });

  return {
    certificate: forge.pki.certificateToPem(cert),
    privateKey: privateKeyPem,
    publicKey: forge.pki.publicKeyToPem(keys.publicKey),
  };
}

/**
 * Generates a leaf signing certificate signed by the Intermediate CA.
 * cA=false, digitalSignature + nonRepudiation — suitable for document signing.
 * Default validity: 2 years (730 days).
 */
export async function generateSigningCertificate(
  intermediateCA: IntermediateCACertificate,
  passphrase: string,
  options: SigningCertificateOptions,
): Promise<SigningCertificate> {
  const { commonName, organization = '', country = '', validityDays = 730 } = options;

  const intermediatePrivateKey = decryptPrivateKey(intermediateCA.privateKey, passphrase);

  const keys = forge.pki.rsa.generateKeyPair({ bits: 2048, workers: -1 });
  const cert = forge.pki.createCertificate();

  cert.publicKey = keys.publicKey;
  cert.serialNumber = crypto.randomBytes(16).toString('hex');

  const now = new Date();
  cert.validity.notBefore = new Date(now.getTime() - 5 * 60 * 1000);
  cert.validity.notAfter = new Date();
  cert.validity.notAfter.setDate(now.getDate() + validityDays);

  const subjectAttrs: forge.pki.CertificateField[] = [{ name: 'commonName', value: commonName }];
  if (organization) subjectAttrs.push({ name: 'organizationName', value: organization });
  if (country) subjectAttrs.push({ name: 'countryName', value: country });

  cert.setSubject(subjectAttrs);

  const intermediateCACert = forge.pki.certificateFromPem(intermediateCA.certificate);
  cert.setIssuer(intermediateCACert.subject.attributes);

  cert.setExtensions([
    {
      name: 'basicConstraints',
      cA: false,
      critical: true,
    },
    {
      name: 'keyUsage',
      digitalSignature: true,
      nonRepudiation: true,
      critical: true,
    },
    {
      name: 'authorityKeyIdentifier',
      keyIdentifier: true,
      authorityCertIssuer: true,
    },
    { name: 'subjectKeyIdentifier' },
  ]);

  cert.sign(intermediatePrivateKey, forge.md.sha256.create());

  const privateKeyPem = forge.pki.encryptRsaPrivateKey(keys.privateKey, passphrase, {
    algorithm: 'aes256',
  });

  return {
    certificate: forge.pki.certificateToPem(cert),
    privateKey: privateKeyPem,
    publicKey: forge.pki.publicKeyToPem(keys.publicKey),
  };
}

/**
 * Verifies the full certificate chain: signing cert → intermediate CA → root CA.
 * Checks expiry, CA constraints, and cryptographic signatures.
 */
export function verifyCertificateChain(
  signingCertPem: string,
  intermediateCAPem: string,
  rootCAPem: string,
): CertificateChainVerificationResult {
  try {
    const signingCert = forge.pki.certificateFromPem(signingCertPem);
    const intermediateCert = forge.pki.certificateFromPem(intermediateCAPem);
    const rootCert = forge.pki.certificateFromPem(rootCAPem);

    const leafConstraints = signingCert.getExtension('basicConstraints') as { cA?: boolean } | null;
    if (leafConstraints?.cA) {
      return { valid: false, error: 'Signing certificate must not be a CA' };
    }

    const now = new Date();
    for (const cert of [signingCert, intermediateCert, rootCert]) {
      if (now < cert.validity.notBefore || now > cert.validity.notAfter) {
        return {
          valid: false,
          error: `Certificate "${cert.subject.getField('CN')?.value}" is expired or not yet valid`,
        };
      }
    }

    if (!intermediateCert.verify(signingCert)) {
      return {
        valid: false,
        error: 'Signing certificate signature is invalid (not signed by Intermediate CA)',
      };
    }

    if (!rootCert.verify(intermediateCert)) {
      return {
        valid: false,
        error: 'Intermediate CA signature is invalid (not signed by Root CA)',
      };
    }

    if (!rootCert.verify(rootCert)) {
      return { valid: false, error: 'Root CA self-signature is invalid' };
    }

    return { valid: true };
  } catch (err) {
    return {
      valid: false,
      error: err instanceof Error ? err.message : 'Verification failed',
    };
  }
}
