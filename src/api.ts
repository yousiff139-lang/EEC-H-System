const IS_DEV = import.meta.env.DEV;
export const API_URL = IS_DEV ? "http://localhost:8000" : "https://eec-h-system-production.up.railway.app";
export const WS_URL = IS_DEV ? "ws://localhost:8000/ws" : "wss://eec-h-system-production.up.railway.app/ws";

const TUNNEL_HEADERS = {
    'Content-Type': 'application/json',
    'bypass-tunnel-reminder': 'true',
};

export const api = {
    async register(payload: any) {
        const res = await fetch(`${API_URL}/register`, {
            method: 'POST',
            headers: TUNNEL_HEADERS,
            body: JSON.stringify(payload)
        });
        if (!res.ok) throw new Error(await res.text());
        return res.json();
    },

    async getLoginContext(username: string) {
        const res = await fetch(`${API_URL}/login-context/${username}`, {
            headers: TUNNEL_HEADERS,
        });
        if (!res.ok) throw new Error(await res.text());
        return res.json();
    },

    async authenticate(payload: any) {
        const res = await fetch(`${API_URL}/auth`, {
            method: 'POST',
            headers: TUNNEL_HEADERS,
            body: JSON.stringify(payload)
        });
        if (!res.ok) throw new Error(await res.text());
        return res.json();
    },

    async getDirectory(username: string) {
        const res = await fetch(`${API_URL}/directory/${username}`, {
            headers: TUNNEL_HEADERS,
        });
        if (!res.ok) throw new Error(await res.text());
        return res.json();
    },

    async sendMessage(payload: any) {
        const res = await fetch(`${API_URL}/messages`, {
            method: 'POST',
            headers: TUNNEL_HEADERS,
            body: JSON.stringify(payload)
        });
        if (!res.ok) throw new Error(await res.text());
        return res.json();
    },

    async resetDatabase() {
        const res = await fetch(`${API_URL}/debug/reset`, {
            method: 'POST',
            headers: TUNNEL_HEADERS,
        });
        if (!res.ok) throw new Error(await res.text());
        return res.json();
    }
};
