export const API_URL = "http://localhost:8000";

export const api = {
    async register(payload: any) {
        const res = await fetch(`${API_URL}/register`, {
            method: 'POST',
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify(payload)
        });
        if (!res.ok) throw new Error(await res.text());
        return res.json();
    },

    async getLoginContext(username: string) {
        const res = await fetch(`${API_URL}/login-context/${username}`);
        if (!res.ok) throw new Error(await res.text());
        return res.json();
    },

    async authenticate(payload: any) {
        const res = await fetch(`${API_URL}/auth`, {
            method: 'POST',
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify(payload)
        });
        if (!res.ok) throw new Error(await res.text());
        return res.json(); // returns { token: "..." }
    },

    async getDirectory(username: string) {
        const res = await fetch(`${API_URL}/directory/${username}`);
        if (!res.ok) throw new Error(await res.text());
        return res.json();
    },

    async sendMessage(payload: any) {
        const res = await fetch(`${API_URL}/messages`, {
            method: 'POST',
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify(payload)
        });
        if (!res.ok) throw new Error(await res.text());
        return res.json();
    }
};
