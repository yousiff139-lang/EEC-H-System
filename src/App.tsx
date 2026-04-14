import { useEffect, useState } from 'react';
import { Shield, Key, Lock, MessageSquare, RotateCcw } from 'lucide-react';
import { motion, AnimatePresence } from 'framer-motion';
import { initSodium } from './crypto/sodium';
import { api } from './api';
import ClientPane from './ClientPane';

function App() {
  const [ready, setReady] = useState(false);

  useEffect(() => {
    initSodium().then(() => setReady(true));
  }, []);

  const handleReset = async () => {
    if (confirm("Clear all user vaults and messages from the server?")) {
      try {
        await api.resetDatabase();
        window.location.reload();
      } catch (e: any) {
        alert("Reset failed: " + e.message);
      }
    }
  };

  if (!ready) {
    return <div className="app-container" style={{ justifyContent: 'center', alignItems: 'center' }}>Initializing WebAssembly Crypto Module...</div>;
  }

  return (
    <div className="app-container">
      <header className="header">
        <div>
          <h1>ZK-E2EE <span>Communication</span></h1>
          <p>Stateless hardware-anchored end-to-end encryption demonstration.</p>
        </div>
        <div style={{ display: 'flex', gap: '8px', alignItems: 'center' }}>
          <button className="btn-secondary" onClick={handleReset} style={{ padding: '8px 12px', fontSize: '0.8rem', display: 'flex', alignItems: 'center', gap: '4px', background: 'rgba(255,255,255,0.05)', marginRight: '16px' }}>
            <RotateCcw size={14} /> Reset Server Data
          </button>
          <span className="badge secure"><Shield size={12} style={{marginRight: 4}}/> WebAuthn PRF Ready</span>
          <span className="badge"><Key size={12} style={{marginRight: 4}}/> Curve25519</span>
          <span className="badge"><Lock size={12} style={{marginRight: 4}}/> XChaCha20-Poly1305</span>
        </div>
      </header>

      <div className="split-view">
        <div className="pane">
            <ClientPane userId="Alice" defaultPeerId="Bob" colorTheme="cyan" />
        </div>
        
        <div className="server-pane">
            <h3 style={{ color: 'var(--text-muted)', marginBottom: '24px' }}>Stateless Mock Server</h3>
            <p style={{ textAlign: 'center', fontSize: '0.85rem' }}>
                The server routes opaque data. It cannot derive keys, and sees only Ciphertext.
            </p>
            {/* Server Activity Animation will go here, triggered top level if we want, or just abstract */}
            <div style={{ marginTop: 'auto', marginBottom: 'auto' }}>
                <motion.div
                   animate={{ y: [0, -10, 0] }}
                   transition={{ repeat: Infinity, duration: 3 }}
                   style={{ opacity: 0.2 }}
                >
                    <Lock size={64} />
                </motion.div>
            </div>
        </div>

        <div className="pane">
            <ClientPane userId="Bob" defaultPeerId="Alice" colorTheme="purple" />
        </div>
      </div>
    </div>
  );
}

export default App;
