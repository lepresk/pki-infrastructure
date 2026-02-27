export interface CACertificate {
  certificate: string; // PEM format
  privateKey: string; // PEM format, AES-256 encrypted
  publicKey: string; // PEM format
}

export interface IntermediateCACertificate {
  certificate: string;
  privateKey: string;
  publicKey: string;
}

export interface SigningCertificate {
  certificate: string;
  privateKey: string;
  publicKey: string;
}

export interface CertificateChainVerificationResult {
  valid: boolean;
  error?: string;
}

export interface IntermediateCAOptions {
  commonName: string;
  organization?: string;
  country?: string;
  validityYears?: number;
}

export interface SigningCertificateOptions {
  commonName: string;
  organization?: string;
  country?: string;
  validityDays?: number;
}
