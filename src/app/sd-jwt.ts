import { Signer, Verifier } from '@hopae/sd-jwt';

/**
 * Encodes an ArrayBuffer into a base64url string
 * @param arrayBuffer
 * @returns
 */
const base64urlEncode = (arrayBuffer: ArrayBuffer) => {
  const uint8Array = new Uint8Array(arrayBuffer);
  const str = String.fromCharCode.apply(null, Array.from(uint8Array));
  let base64 = btoa(str);
  return base64.replace('+', '-').replace('/', '_').replace(/=+$/, '');
};

/**
 * Decodes a base64url string into an ArrayBuffer
 * @param base64url
 * @returns
 */
function base64urlToArrayBuffer(base64url: string) {
  let base64 = base64url.replace('-', '+').replace('_', '/');
  while (base64.length % 4) {
    base64 += '=';
  }
  const binary_string = atob(base64);
  const len = binary_string.length;
  const bytes = new Uint8Array(len);
  for (let i = 0; i < len; i++) {
    bytes[i] = binary_string.charCodeAt(i);
  }
  return bytes.buffer;
}

/**
 * Creates a signer and verifier pair
 * @returns
 */
export const createSignerVerifier = async () => {
  const keypair = await window.crypto.subtle.generateKey(
    { name: 'ECDSA', namedCurve: 'P-256' },
    true,
    ['sign', 'verify']
  );
  const signer: Signer = async (data: string) => {
    let enc = new TextEncoder();
    const sig = await window.crypto.subtle.sign(
      { name: 'ECDSA', hash: 'SHA-256' },
      keypair.privateKey,
      enc.encode(data)
    );
    return base64urlEncode(sig);
  };
  const verifier: Verifier = async (data: string, sig: string) => {
    const dec = new TextEncoder();
    return window.crypto.subtle.verify(
      { name: 'ECDSA', hash: 'SHA-256' },
      keypair.publicKey,
      base64urlToArrayBuffer(sig),
      dec.encode(data)
    );
  };
  return { signer, verifier };
};

/**
 * Generates a random salt
 * @param length
 * @returns
 */
export const generateSalt = (length: number): string => {
  const saltBytes = new Uint8Array(length);
  window.crypto.getRandomValues(saltBytes);
  let salt = '';
  for (let i = 0; i < saltBytes.length; i++) {
    salt += saltBytes[i].toString(16).padStart(2, '0');
  }
  return salt;
};

/**
 * Hashes a string using a given algorithm
 * @param data
 * @param algorithm
 * @returns
 */
export const digest = async (
  data: string,
  algorithm: string = 'SHA-256'
): Promise<Uint8Array> => {
  const encoder = new TextEncoder();
  const dataUint8Array = encoder.encode(data);
  const hashBuffer = await window.crypto.subtle.digest(
    algorithm,
    dataUint8Array
  );
  return new Uint8Array(hashBuffer);
};
