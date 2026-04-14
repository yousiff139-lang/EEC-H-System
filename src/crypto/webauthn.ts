/**
 * WebAuthn core wrapper handling PRF extraction and Fallback modes.
 */

// Helper to encode ArrayBuffer to Base64URL
export function bufferToBase64URL(buffer: ArrayBuffer): string {
    const bytes = new Uint8Array(buffer);
    let str = "";
    for (const charCode of bytes) {
        str += String.fromCharCode(charCode);
    }
    const base64 = btoa(str);
    return base64.replace(/\+/g, "-").replace(/\//g, "_").replace(/=/g, "");
}

// Generate random salt for PRF
export const generatePrfSalt = (): Uint8Array => {
    const salt = new Uint8Array(32);
    window.crypto.getRandomValues(salt);
    return salt;
};

export const registerWithPrf = async (username: string, prfSalt: Uint8Array): Promise<{ ikm: Uint8Array, credentialId: string }> => {
    const challenge = new Uint8Array(32);
    window.crypto.getRandomValues(challenge);

    const userId = new Uint8Array(16);
    window.crypto.getRandomValues(userId);

    try {
        const credential = await navigator.credentials.create({
            publicKey: {
                challenge,
                rp: { id: window.location.hostname, name: "ZK-E2EE App" },
                user: { id: userId, name: username, displayName: username },
                pubKeyCredParams: [
                    { type: "public-key", alg: -7 },  // ES256
                    { type: "public-key", alg: -8 }   // EdDSA
                ],
                authenticatorSelection: {
                    userVerification: "preferred"
                },
                extensions: {
                    prf: {
                        eval: { first: prfSalt }
                    }
                } as any
            }
        }) as PublicKeyCredential;

        // Extract ID
        const credentialId = bufferToBase64URL(credential.rawId);

        // Fetch PRF capability result
        const results = credential.getClientExtensionResults() as any;
        console.log("WebAuthn Extension Results:", results);

        if (results.prf && results.prf.results && results.prf.results.first) {
            return {
                ikm: new Uint8Array(results.prf.results.first),
                credentialId
            };
        } else {
            console.warn("Authenticator does not support PRF. Triggering FALLBACK SIMULATION MODE.");
            return triggerFallbackPrf(prfSalt, username, credentialId);
        }
    } catch (error) {
        console.error("WebAuthn Create Error:", error);
        return triggerFallbackPrf(prfSalt, username, "simulated-id-for-"+username);
    }
};

export const authenticateWithPrf = async (credentialId: string, prfSalt: Uint8Array, username: string): Promise<Uint8Array> => {
    const challenge = new Uint8Array(32);
    window.crypto.getRandomValues(challenge);

    // If it's a simulated ID, skip WebAuthn entirely to allow demo to function
    if (credentialId.startsWith("simulated-id-")) {
        console.warn("Using simulated authentication fallback (Simulated ID)...");
        return (await triggerFallbackPrf(prfSalt, username, credentialId)).ikm;
    }

    // Decode CredentialId to buffer
    let base64 = credentialId.replace(/-/g, "+").replace(/_/g, "/");
    while (base64.length % 4 !== 0) {
        base64 += "=";
    }
    const idBuffer = Uint8Array.from(atob(base64), c => c.charCodeAt(0));

    try {
        const credential = await navigator.credentials.get({
            publicKey: {
                challenge,
                rpId: window.location.hostname,
                allowCredentials: [{
                    type: "public-key",
                    id: idBuffer
                }],
                userVerification: "preferred",
                extensions: {
                    prf: {
                        eval: { first: prfSalt }
                    }
                } as any
            }
        }) as PublicKeyCredential;

        const results = credential.getClientExtensionResults() as any;
        if (results.prf && results.prf.results && results.prf.results.first) {
            return new Uint8Array(results.prf.results.first);
        } else {
            console.warn("Authenticator returned successfully but PRF was missing. Triggering FALLBACK SIMULATION.");
            return (await triggerFallbackPrf(prfSalt, username, credentialId)).ikm;
        }
    } catch (e) {
        console.error("WebAuthn Auth Error - falling back to simulation:", e);
        return (await triggerFallbackPrf(prfSalt, username, credentialId)).ikm;
    }
};

// Fallback logic for devices without PRF
// Uses a static HKDF based on the username to simulate a deterministic hardware secret
const triggerFallbackPrf = async (salt: Uint8Array, username: string, credentialId: string) => {
    const enc = new TextEncoder();
    const baseMaterial = enc.encode("fallback-hardware-secret-" + username);
    
    // Simple SHA-256 derivation to simulate deterministic output of PRF based on salt
    const dataToHash = new Uint8Array(baseMaterial.length + salt.length);
    dataToHash.set(baseMaterial);
    dataToHash.set(salt, baseMaterial.length);

    const hash = await window.crypto.subtle.digest("SHA-256", dataToHash);
    return { ikm: new Uint8Array(hash), credentialId };
};
