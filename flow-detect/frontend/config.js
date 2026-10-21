/**
 * Auto-Discovery Backend Configuration (`config.js`)
 *
 * Works with ZERO manual IP edits across ALL 3 environments:
 *  1. `frontend_server.py` proxy on Port 9012 / Cloud / HTTPS Preview -> uses same-origin `/api` & `/ws/live`
 *  2. Plain `python -m http.server 9012` on Wi-Fi (`http://192.168.62.52:9012`) -> auto-discovers `http://192.168.62.52:8000`!
 *  3. Optional URL query override `?api=http://192.168.62.52:8000`
 */
window.FlowDetectConfig = {
  apiBase: "",
  wsUrl: "",

  async init() {
    const params = new URLSearchParams(window.location.search);
    const manualApi = params.get("api");
    if (manualApi) {
      const clean = manualApi.replace(/\/$/, "");
      this.apiBase = clean;
      this.wsUrl = clean.replace(/^http/, "ws") + "/ws/live";
      return this;
    }

    // First probe relative `/api/security/status` (works on frontend_server.py proxy & HTTPS previews)
    try {
      const res = await fetch("/api/security/status", { cache: "no-store" });
      if (res.ok) {
        this.apiBase = "";
        const proto = window.location.protocol === "https:" ? "wss:" : "ws:";
        this.wsUrl = `${proto}//${window.location.host}/ws/live`;
        return this;
      }
    } catch (_) {
      // Fall through to port 8000 on current hostname (e.g. `python -m http.server 9012`)
    }

    // Fallback for plain `python -m http.server 9012` on `192.168.62.52` or Cloud VM IP!
    const host = window.location.hostname || "127.0.0.1";
    const httpProto = window.location.protocol === "https:" ? "https:" : "http:";
    const wsProto = window.location.protocol === "https:" ? "wss:" : "ws:";
    this.apiBase = `${httpProto}//${host}:8000`;
    this.wsUrl = `${wsProto}//${host}:8000/ws/live`;
    return this;
  },
};
