// Typed REST client for the corplink-web control-panel API. Every endpoint the
// Go server exposes has a matching function here. Errors are normalized to an
// ApiError carrying the server's {"error": "..."} message.

export type ConnState =
  | "logged_out"
  | "logged_in"
  | "connecting"
  | "connected"
  | "disconnecting";

export interface State {
  state: ConnState;
  need_company: boolean;
  company_name: string;
  username: string;
  server_id: number;
  server_name: string;
  connected: boolean;
  proxy_listen: string;
  admin_required: boolean;
  error?: string;
}

export interface CompanyInfo {
  company_name: string;
  zh_name: string;
  en_name: string;
  server: string;
}

export interface TpsOption {
  alias: string;
  login_url: string;
  token: string;
}

export interface LoginMethods {
  login_orders: string[] | null;
  login_enable_ldap: boolean;
  login_enable: boolean;
  tps: TpsOption[] | null;
}

export interface Server {
  id: number;
  name: string;
  en_name: string;
  ip: string;
  latency_ms: number;
  protocol_mode: number;
  selected: boolean;
}

export interface Traffic {
  connected: boolean;
  tx_bps: number;
  rx_bps: number;
  tx_total: number;
  rx_total: number;
  proxy_listen: string;
  since: number;
}

export interface ConfigView {
  socks_listen: string;
  vpn_server_id: number;
  vpn_select_strategy: string;
  route_mode: string;
  force_protocol: string;
  company_name: string;
  username: string;
}

export interface AdminAuth {
  enabled: boolean;
  authenticated: boolean;
}

export class ApiError extends Error {
  status: number;
  constructor(status: number, message: string) {
    super(message);
    this.status = status;
  }
}

async function req<T>(
  path: string,
  init?: RequestInit & { json?: unknown }
): Promise<T> {
  const opts: RequestInit = { ...init };
  if (init?.json !== undefined) {
    opts.body = JSON.stringify(init.json);
    opts.headers = { ...(init.headers || {}), "Content-Type": "application/json" };
  }
  const resp = await fetch(path, opts);
  const text = await resp.text();
  let data: unknown = undefined;
  if (text) {
    try {
      data = JSON.parse(text);
    } catch {
      data = text;
    }
  }
  if (!resp.ok) {
    const msg =
      (data && typeof data === "object" && "error" in data
        ? String((data as Record<string, unknown>).error)
        : resp.statusText) || "请求失败";
    throw new ApiError(resp.status, msg);
  }
  return data as T;
}

export const api = {
  state: () => req<State>("/api/state"),
  setCompany: (company_name: string) =>
    req<CompanyInfo>("/api/company", { method: "POST", json: { company_name } }),
  loginMethods: () => req<LoginMethods>("/api/login/methods"),
  loginPassword: (username: string, password: string, platform: string) =>
    req<{ ok?: boolean; need_otp?: boolean }>("/api/login/password", {
      method: "POST",
      json: { username, password, platform },
    }),
  emailRequest: (username: string) =>
    req<{ ok: boolean }>("/api/login/email/request", {
      method: "POST",
      json: { username },
    }),
  emailVerify: (username: string, code: string) =>
    req<{ ok: boolean }>("/api/login/email/verify", {
      method: "POST",
      json: { username, code },
    }),
  tpsCheck: (token: string) =>
    req<{ ok: boolean; pending: boolean; url?: string }>(
      `/api/login/tps/check?token=${encodeURIComponent(token)}`
    ),
  connect: (server_id?: number, otp?: string) =>
    req<{ state: ConnState; need_otp?: boolean }>("/api/connect", {
      method: "POST",
      json: { server_id: server_id ?? 0, otp: otp ?? "" },
    }),
  disconnect: () =>
    req<{ state: ConnState }>("/api/disconnect", { method: "POST" }),
  servers: (probe = true) =>
    req<{ servers: Server[] }>(`/api/servers?probe=${probe ? "true" : "false"}`),
  traffic: () => req<Traffic>("/api/traffic"),
  logout: () => req<{ ok: boolean }>("/api/logout", { method: "POST" }),
  getConfig: () => req<ConfigView>("/api/config"),
  putConfig: (patch: Partial<Record<string, unknown>>) =>
    req<{ ok: boolean }>("/api/config", { method: "PUT", json: patch }),
  adminAuth: () => req<AdminAuth>("/api/admin/auth"),
  adminLogin: (username: string, password: string) =>
    req<{ ok: boolean }>("/api/admin/login", {
      method: "POST",
      json: { username, password },
    }),
  adminLogout: () =>
    req<{ ok: boolean }>("/api/admin/logout", { method: "POST" }),
};

// --- formatting helpers ---

export function formatRate(bps: number): string {
  const bytesPerSec = bps; // server reports bytes/sec
  const units = ["B/s", "KB/s", "MB/s", "GB/s"];
  let v = bytesPerSec;
  let i = 0;
  while (v >= 1024 && i < units.length - 1) {
    v /= 1024;
    i++;
  }
  return `${v.toFixed(v >= 100 || i === 0 ? 0 : 1)} ${units[i]}`;
}

export function formatBytes(n: number): string {
  const units = ["B", "KB", "MB", "GB", "TB"];
  let v = n;
  let i = 0;
  while (v >= 1024 && i < units.length - 1) {
    v /= 1024;
    i++;
  }
  return `${v.toFixed(v >= 100 || i === 0 ? 0 : 1)} ${units[i]}`;
}
