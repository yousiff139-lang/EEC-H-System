export async function deriveHKDF(
  ikm: Uint8Array,
  infoString: string,
  saltSize: number = 32
): Promise<Uint8Array> {
  // 1. Import raw IKM into WebCrypto as a base key
  const baseKey = await window.crypto.subtle.importKey(
    'raw',
    ikm,
    { name: 'HKDF' },
    false,
    ['deriveBits', 'deriveKey']
  );

  // 2. Define standard salt (For simplicity in this demo, using a zero-salt or fixed string, 
  // though typically salt is provided by the server or tied to user.)
  const salt = new Uint8Array(saltSize).fill(0); 

  // 3. Define Info
  const encoder = new TextEncoder();
  const info = encoder.encode(infoString);

  // 4. Derive symmetric WrapKey (32 bytes = 256 bits for XChaCha20)
  const derivedBits = await window.crypto.subtle.deriveBits(
    {
      name: 'HKDF',
      hash: 'SHA-256',
      salt,
      info,
    },
    baseKey,
    256
  );

  return new Uint8Array(derivedBits);
}
