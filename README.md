# certforge

![Build a Complete PKI from Scratch in Node.js](https://lepresk.com/storage/posts/featured-images/01KHNYFVHQ74AK5HPTT59EK614.webp)

Node.js implementation of a three-tier Public Key Infrastructure — Root CA, Intermediate CA, and leaf signing certificates — using `node-forge` and the built-in `crypto` module.

This is the companion code for the article: [Build a Complete PKI from Scratch in Node.js](https://lepresk.com/blog/build-a-complete-pki-from-scratch-in-nodejs)

## Requirements

- Node.js 20 or later
- pnpm

## Getting started

```bash
pnpm install
pnpm dev
```

## What it does

Running the demo generates a full certificate chain and exercises signing and verification:

1. Creates a self-signed Root CA (4096-bit RSA, 10-year validity)
2. Issues an Intermediate CA signed by the Root CA (2048-bit, 5-year validity)
3. Issues a leaf signing certificate signed by the Intermediate CA (2048-bit, 2-year validity)
4. Verifies the certificate chain
5. Signs a document and verifies the signature against the original and a tampered version

Certificates are written to `pki/` as PEM files. That directory is excluded from git — never commit private keys.

## Project structure

```
src/
  types.ts     — shared interfaces
  crypto.ts    — key decryption, sign, verify
  pki.ts       — CA and certificate generation, chain verification
  storage.ts   — read/write PEM files
  index.ts     — end-to-end demo
```

## A note on AES-256 key decryption

`node-forge` silently returns `null` when decrypting AES-256 encrypted private keys in some Node.js versions. The workaround in `src/crypto.ts` uses the built-in `crypto` module to decrypt the key and re-exports it as unencrypted PKCS#1 before handing it back to forge. See the article for a full explanation.

## License

MIT
