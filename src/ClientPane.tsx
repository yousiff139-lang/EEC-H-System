import { useState, useEffect, useRef } from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import { api, WS_URL } from './api';
import { generatePrfSalt, registerWithPrf, authenticateWithPrf, bufferToBase64URL } from './crypto/webauthn';
import { deriveHKDF } from './crypto/hkdf';
import { sodium, generateIdentityKeyPair, generateMessagingKeyPair, wrapVault, unwrapVault, purgeMemory, deriveSharedSecret, encryptMessage, decryptMessage } from './crypto/sodium';
import { Fingerprint, LockOpen, Send, UserCheck, Shield } from 'lucide-react';

export default function ClientPane({ userId, defaultPeerId, colorTheme }: { userId: string, defaultPeerId: string, colorTheme: string }) {
    const [status, setStatus] = useState<"logged_out" | "registering" | "logging_in" | "ready">("logged_out");
    const [token, setToken] = useState("");
    const [messages, setMessages] = useState<{from: string, text: string}[]>([]);
    const [input, setInput] = useState("");
    const [ws, setWs] = useState<WebSocket | null>(null);

    // Volatile Memory!
    const volatileMemory = useRef<any>(null); // holds privateEd25519, privateX25519

    useEffect(() => { return () => { if(ws) ws.close(); } }, [ws]);

    const doRegister = async () => {
        try {
            setStatus("registering");
            console.log(`[${userId}] Generating PRF Salt...`);
            const prfSalt = generatePrfSalt();
            
            console.log(`[${userId}] Calling WebAuthn...`);
            const authResult = await registerWithPrf(userId, prfSalt);
            
            console.log(`[${userId}] Deriving WrapKey via HKDF...`);
            const wrapKey = await deriveHKDF(authResult.ikm, "chat_wrap_key_v1");

            console.log(`[${userId}] Generating Identity & Messaging Keys...`);
            const idKey = generateIdentityKeyPair();
            const msgKey = generateMessagingKeyPair();

            const vaultData = {
                privateIdentityKeyHex: sodium.to_hex(idKey.privateKey),
                privateMessagingKeyHex: sodium.to_hex(msgKey.privateKey)
            };

            const { ciphertext, nonce } = wrapVault(vaultData, wrapKey);

            await api.register({
                username: userId,
                credential_id: authResult.credentialId,
                prf_salt_hex: sodium.to_hex(prfSalt),
                public_identity_key_hex: sodium.to_hex(idKey.publicKey),
                public_messaging_key_hex: sodium.to_hex(msgKey.publicKey),
                vault_ciphertext_hex: sodium.to_hex(ciphertext),
                vault_nonce_hex: sodium.to_hex(nonce)
            });

            // Clean up IKMs
            purgeMemory(authResult.ikm);
            purgeMemory(wrapKey);

            setStatus("logged_out");
            alert(`${userId} registered successfully! You can now authenticate.`);
        } catch (e: any) {
            console.error(e);
            alert("Registration failed: " + e.message);
            setStatus("logged_out");
        }
    };

    const doAuthenticate = async () => {
        try {
            setStatus("logging_in");
            // 1. Fetch encrypted vault and salt
            const ctx = await api.getLoginContext(userId);
            
            // 2. Call WebAuthn to reconstruct PRF output
            const prfSalt = sodium.from_hex(ctx.prf_salt_hex);
            const ikm = await authenticateWithPrf(ctx.credential_id, prfSalt, userId);

            // 3. Re-derive WrapKey
            const wrapKey = await deriveHKDF(ikm, "chat_wrap_key_v1");

            // 4. Unwrap vault into volatile memory
            const vaultCiphertext = sodium.from_hex(ctx.vault_ciphertext_hex);
            const vaultNonce = sodium.from_hex(ctx.vault_nonce_hex);
            const vaultData = unwrapVault(vaultCiphertext, vaultNonce, wrapKey);

            volatileMemory.current = {
                privateIdentityKey: sodium.from_hex(vaultData.privateIdentityKeyHex),
                privateMessagingKey: sodium.from_hex(vaultData.privateMessagingKeyHex)
            };

            purgeMemory(ikm);
            purgeMemory(wrapKey);

            // 5. Zero-Knowledge Proof to Auth Server
            const timestamp = Date.now();
            const msgToSign = new TextEncoder().encode(timestamp.toString());
            const signature = sodium.crypto_sign_detached(msgToSign, volatileMemory.current.privateIdentityKey);

            const authRes = await api.authenticate({
                username: userId,
                timestamp,
                signature_hex: sodium.to_hex(signature)
            });

            setToken(authRes.token);
            connectWebSocket(authRes.token);
            setStatus("ready");

        } catch (e: any) {
            console.error(e);
            alert("Authentication failed: " + e.message);
            setStatus("logged_out");
        }
    };

    const connectWebSocket = (jwt: string) => {
        const socket = new WebSocket(`${WS_URL}?token=${jwt}`);
        socket.onmessage = async (event) => {
            const data = JSON.parse(event.data);
            if (data.type === "new_message") {
                await processIncomingMessage(data.message);
            } else if (data.type === "sync") {
                for (let m of data.messages) await processIncomingMessage(m);
            }
        };
        setWs(socket);
    };

    // Keep peer keys cached so we don't spam api
    const peerCache = useRef<Record<string, any>>({});

    const getPeerKeys = async (peerId: string) => {
        if (!peerCache.current[peerId]) {
            peerCache.current[peerId] = await api.getDirectory(peerId);
        }
        return peerCache.current[peerId];
    };

    const processIncomingMessage = async (msg: any) => {
        if (msg.from_id === userId) return; // ignore self
        try {
            const peer = await getPeerKeys(msg.from_id);
            const pkMsg = sodium.from_hex(peer.public_messaging_key_hex);
            
            // X25519 ECDH compute
            const sharedSecret = deriveSharedSecret(volatileMemory.current.privateMessagingKey, pkMsg);
            
            // Wait, we need to hash the shared secret per HKDF spec usually, but for demo:
            const symKey = await deriveHKDF(sharedSecret, "chat_e2ee_v1");
            
            const plaintext = decryptMessage(msg.ciphertext_hex, msg.nonce_hex, symKey);
            
            // Also we would verify Ed25519 signature of the ciphertext in a real client, 
            // but the server already validated it to prevent spam. For true E2EE we do it here too:
            const payloadToVerify = new TextEncoder().encode(`${msg.from_id}:${msg.to_id}:${msg.ciphertext_hex}:${msg.nonce_hex}`);
            const isValid = sodium.crypto_sign_verify_detached(
                sodium.from_hex(msg.signature_hex),
                payloadToVerify,
                sodium.from_hex(peer.public_identity_key_hex)
            );

            if (!isValid) throw new Error("Invalid signature from peer!");

            setMessages(prev => [...prev, {from: msg.from_id, text: plaintext}]);
        } catch(e) {
            console.error("Failed to process message", e);
        }
    };

    const sendMessage = async () => {
        if (!input.trim()) return;
        try {
            const peer = await getPeerKeys(defaultPeerId);
            const pkMsg = sodium.from_hex(peer.public_messaging_key_hex);
            
            // 1. ECDH
            const sharedSecret = deriveSharedSecret(volatileMemory.current.privateMessagingKey, pkMsg);
            const symKey = await deriveHKDF(sharedSecret, "chat_e2ee_v1");

            // 2. Encrypt
            const { ciphertext, nonce } = encryptMessage(input, symKey);

            // 3. Sign
            const payloadToSign = new TextEncoder().encode(`${userId}:${defaultPeerId}:${ciphertext}:${nonce}`);
            const signature = sodium.crypto_sign_detached(payloadToSign, volatileMemory.current.privateIdentityKey);

            // 4. Send
            await api.sendMessage({
                from_id: userId,
                to_id: defaultPeerId,
                ciphertext_hex: ciphertext,
                nonce_hex: nonce,
                signature_hex: sodium.to_hex(signature)
            });

            setMessages(prev => [...prev, {from: userId, text: input}]);
            setInput("");
        } catch (e: any) {
            alert("Send failed. Is peer registered?");
        }
    };

    const colorVars = colorTheme === "cyan" ? { 
        border: 'var(--accent-cyan)', 
        bg: 'rgba(6, 182, 212, 0.1)' 
    } : { 
        border: 'var(--accent-purple)', 
        bg: 'rgba(139, 92, 246, 0.1)' 
    };

    return (
        <div className="glass-panel" style={{ height: '100%', display: 'flex', flexDirection: 'column', borderTop: `4px solid ${colorVars.border}` }}>
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '24px' }}>
                <h2 style={{ margin: 0, display: 'flex', alignItems: 'center', gap: '8px' }}>
                    <UserCheck size={20} color={colorVars.border} /> Device: {userId}
                </h2>
                {status === "ready" && <span className="badge secure">Vault Unlocked</span>}
            </div>

            {status !== "ready" ? (
                <div style={{ flex: 1, display: 'flex', flexDirection: 'column', justifyContent: 'center', alignItems: 'center', gap: '16px' }}>
                    <Fingerprint size={48} color={colorVars.border} style={{ opacity: 0.8 }} />
                    <p style={{ textAlign: 'center' }}>Secure your identity purely via hardware authenticator. No passwords stored.</p>
                    
                    <button className="btn-primary" onClick={doRegister} disabled={status !== "logged_out"} style={{ width: '200px' }}>
                        {status === "registering" ? "Enrolling..." : "Register Vault"}
                    </button>
                    <button className="btn-secondary" onClick={doAuthenticate} disabled={status !== "logged_out"} style={{ width: '200px' }}>
                        {status === "logging_in" ? "Authenticating..." : "Login (Hardware PRF)"}
                    </button>
                </div>
            ) : (
                <div style={{ flex: 1, display: 'flex', flexDirection: 'column' }}>
                    <div style={{ flex: 1, overflowY: 'auto', marginBottom: '16px', display: 'flex', flexDirection: 'column' }}>
                        <AnimatePresence>
                            {messages.map((m, i) => (
                                <motion.div 
                                    key={i}
                                    initial={{ opacity: 0, y: 10 }}
                                    animate={{ opacity: 1, y: 0 }}
                                    className={`message-bubble ${m.from === userId ? 'sent' : 'received'}`}
                                >
                                    {m.text}
                                </motion.div>
                            ))}
                        </AnimatePresence>
                        {messages.length === 0 && <p style={{ textAlign: 'center', marginTop: 'auto', marginBottom: 'auto' }}>No messages yet.</p>}
                    </div>
                    
                    <div style={{ display: 'flex', gap: '8px' }}>
                        <input 
                            className="input-base" 
                            type="text" 
                            placeholder={`Message ${defaultPeerId}...`} 
                            value={input}
                            onChange={e => setInput(e.target.value)}
                            onKeyDown={e => e.key === 'Enter' && sendMessage()}
                        />
                        <button className="btn-primary" onClick={sendMessage} style={{ padding: '12px' }}>
                            <Send size={18} />
                        </button>
                    </div>
                </div>
            )}
        </div>
    );
}
