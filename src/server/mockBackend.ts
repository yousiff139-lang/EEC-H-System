// This models the ZERO-KNOWLEDGE SERVER described in the blueprint.
// The server stores NO passwords, NO raw keys. 
// It only houses public keys, the WebAuthn salt (PRF), and encrypted XChaCha20 blobs (Vault + Messages).

export interface UserProfile {
  id: string; // e.g., 'Alice'
  credentialId: string;
  prfSaltHex: string; // The salt used to re-derive the wrap key
  publicIdentityKeyHex: string; // Ed25519
  publicMessagingKeyHex: string; // X25519
  vaultCiphertextHex: string; // The private keys encrypted with WrapKey
  vaultNonceHex: string;
}

export interface EncryptedMessage {
  id: string;
  fromId: string;
  toId: string;
  ciphertextHex: string;
  nonceHex: string;
  timestamp: number;
}

class ZeroKnowledgeServer {
  private users: Map<string, UserProfile> = new Map();
  private messages: EncryptedMessage[] = [];
  
  // Listeners for UI reactivity
  private messageListeners: ((messages: EncryptedMessage[]) => void)[] = [];

  // --- Registration / Login ---
  
  public registerProfile(profile: UserProfile): void {
    if (this.users.has(profile.id)) {
      throw new Error("User already exists");
    }
    this.users.set(profile.id, profile);
    console.log(`[SERVER] Registered purely opaque data for ${profile.id}`);
  }

  public getLoginContext(id: string): { prfSaltHex: string, credentialId: string, vaultCiphertextHex: string, vaultNonceHex: string } {
    const user = this.users.get(id);
    if (!user) throw new Error("User not found");
    return {
      prfSaltHex: user.prfSaltHex,
      credentialId: user.credentialId,
      vaultCiphertextHex: user.vaultCiphertextHex,
      vaultNonceHex: user.vaultNonceHex
    };
  }

  public getPublicKey(id: string): string {
    const user = this.users.get(id);
    if (!user) throw new Error("User not found");
    return user.publicMessagingKeyHex; // Send X25519 key
  }

  public isRegistered(id: string): boolean {
    return this.users.has(id);
  }

  // --- Messaging (Zero-Knowledge) ---

  public sendMessage(msg: Omit<EncryptedMessage, "id" | "timestamp">) {
    const newMessage: EncryptedMessage = {
      ...msg,
      id: Math.random().toString(36).substring(7),
      timestamp: Date.now()
    };
    this.messages.push(newMessage);
    console.log(`[SERVER] Routing opaque blob from ${msg.fromId} to ${msg.toId}`);
    this.notifyListeners();
  }

  // Real-time listener for the destination client
  public onMessagesChange(callback: (messages: EncryptedMessage[]) => void) {
    this.messageListeners.push(callback);
    // Send initial
    callback(this.messages);
    return () => {
      this.messageListeners = this.messageListeners.filter(l => l !== callback);
    };
  }

  private notifyListeners() {
    this.messageListeners.forEach(listener => listener([...this.messages]));
  }
}

export const mockServer = new ZeroKnowledgeServer();
