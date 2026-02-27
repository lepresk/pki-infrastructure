import fs from 'fs/promises';
import path from 'path';
import type { CACertificate, IntermediateCACertificate, SigningCertificate } from './types.js';

async function writePemFiles(
  dir: string,
  files: Record<string, string>,
): Promise<void> {
  await fs.mkdir(dir, { recursive: true });
  await Promise.all(
    Object.entries(files).map(([filename, content]) =>
      fs.writeFile(path.join(dir, filename), content, { encoding: 'utf-8', mode: 0o600 }),
    ),
  );
}

export async function saveRootCA(ca: CACertificate, dir: string): Promise<void> {
  await writePemFiles(dir, {
    'cert.pem': ca.certificate,
    'key.pem': ca.privateKey,
    'public.pem': ca.publicKey,
  });
}

export async function loadRootCA(dir: string): Promise<CACertificate> {
  const [certificate, privateKey, publicKey] = await Promise.all([
    fs.readFile(path.join(dir, 'cert.pem'), 'utf-8'),
    fs.readFile(path.join(dir, 'key.pem'), 'utf-8'),
    fs.readFile(path.join(dir, 'public.pem'), 'utf-8'),
  ]);
  return { certificate, privateKey, publicKey };
}

export async function saveIntermediateCA(
  ca: IntermediateCACertificate,
  dir: string,
): Promise<void> {
  await writePemFiles(dir, {
    'cert.pem': ca.certificate,
    'key.pem': ca.privateKey,
    'public.pem': ca.publicKey,
  });
}

export async function loadIntermediateCA(dir: string): Promise<IntermediateCACertificate> {
  const [certificate, privateKey, publicKey] = await Promise.all([
    fs.readFile(path.join(dir, 'cert.pem'), 'utf-8'),
    fs.readFile(path.join(dir, 'key.pem'), 'utf-8'),
    fs.readFile(path.join(dir, 'public.pem'), 'utf-8'),
  ]);
  return { certificate, privateKey, publicKey };
}

export async function saveSigningCertificate(
  cert: SigningCertificate,
  dir: string,
): Promise<void> {
  await writePemFiles(dir, {
    'cert.pem': cert.certificate,
    'key.pem': cert.privateKey,
    'public.pem': cert.publicKey,
  });
}

export async function loadSigningCertificate(dir: string): Promise<SigningCertificate> {
  const [certificate, privateKey, publicKey] = await Promise.all([
    fs.readFile(path.join(dir, 'cert.pem'), 'utf-8'),
    fs.readFile(path.join(dir, 'key.pem'), 'utf-8'),
    fs.readFile(path.join(dir, 'public.pem'), 'utf-8'),
  ]);
  return { certificate, privateKey, publicKey };
}
