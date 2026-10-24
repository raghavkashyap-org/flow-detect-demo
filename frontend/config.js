/**
 * FlowDetect Universal Backend Auto-Discovery (`config.js`)
 *
 * Works seamlessly with zero manual IP edits across every deployment setup:
 *   1. Explicit URL parameter override (`?api=http://203.0.113.10:8000`)
 *   2. Same-origin reverse proxy (`frontend_server.py` on :9012 / Nginx / HTTPS preview)
 *   3. Any static HTTP server port on LAN / Windows / Linux (`http.server 9090`, `5500`, `3000`, Vite)
 *      -> automatically targets `http://<window.location.hostname>:8000` & `ws://<hostname>:8000/ws/live`
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

    // Tier 1: Probe relative `/api/security/status` (reverse proxy mode)
    try {
      const res = await fetch("/api/security/status", { cache: "no-store" });
      const ctype = res.headers.get("content-type") || "";
      if (res.ok && ctype.includes("application/json")) {
        this.apiBase = "";
        const proto = window.location.protocol === "https:" ? "wss:" : "ws:";
        this.wsUrl = `${proto}//${window.location.host}/ws/live`;
        return this;
      }
    } catch (_) {
      // Expected on standalone static servers (`http.server`, `http-server`, Vite)
    }

    // Tier 2: Direct LAN / localhost / Cloud host on port 8000
    const host = window.location.hostname || "127.0.0.1";
    const httpProto = window.location.protocol === "https:" ? "https:" : "http:";
    const wsProto = window.location.protocol === "https:" ? "wss:" : "ws:";
    this.apiBase = `${httpProto}//${host}:8000`;
    this.wsUrl = `${wsProto}//${host}:8000/ws/live`;
    return this;
  },
};
