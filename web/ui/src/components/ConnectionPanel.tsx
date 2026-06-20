import { useEffect, useState } from "react";
import { api, type State, type Traffic } from "../api";
import { Button } from "../ui/Button";
import { TrafficFlow } from "./TrafficFlow";
import { Copy, Check, Power, Plug, Loader2 } from "lucide-react";

export function ConnectionPanel({
  state,
  onChanged,
}: {
  state: State;
  onChanged: () => void;
}) {
  const [traffic, setTraffic] = useState<Traffic | null>(null);
  const [busy, setBusy] = useState(false);
  const [copied, setCopied] = useState(false);
  const connected = state.state === "connected";
  const connecting = state.state === "connecting";

  useEffect(() => {
    if (!connected) {
      setTraffic(null);
      return;
    }
    let alive = true;
    const tick = () => api.traffic().then((t) => alive && setTraffic(t)).catch(() => {});
    tick();
    const id = setInterval(tick, 1500);
    return () => {
      alive = false;
      clearInterval(id);
    };
  }, [connected]);

  async function disconnect() {
    setBusy(true);
    try {
      await api.disconnect();
      onChanged();
    } finally {
      setBusy(false);
    }
  }

  function copyProxy() {
    const addr = traffic?.proxy_listen || state.proxy_listen;
    navigator.clipboard?.writeText(addr).then(() => {
      setCopied(true);
      setTimeout(() => setCopied(false), 1500);
    });
  }

  if (!connected && !connecting) {
    return (
      <div className="flex flex-col items-center gap-2 rounded-2xl border border-dashed border-cream-400 bg-cream-200/40 px-4 py-7 text-center">
        <div className="flex h-10 w-10 items-center justify-center rounded-full bg-cream-300 text-ink-faint">
          <Plug className="h-5 w-5" />
        </div>
        <p className="text-sm text-ink-muted">
          选择一个节点并连接，连接成功后即可使用代理。
        </p>
      </div>
    );
  }

  if (connecting) {
    return (
      <div className="space-y-4">
        <div className="flex items-center justify-between">
          <div className="flex items-center gap-2.5">
            <Loader2 className="h-4 w-4 animate-spin text-burnt" />
            <div className="leading-tight">
              <p className="text-sm font-semibold text-burnt">建立加密通道…</p>
              <p className="text-xs text-ink-muted">{state.server_name || "正在握手"}</p>
            </div>
          </div>
        </div>
        <TrafficFlow traffic={null} serverName={state.server_name} mode="connecting" />
      </div>
    );
  }

  const proxyAddr = traffic?.proxy_listen || state.proxy_listen;

  return (
    <div className="space-y-5">
      {/* live connection header */}
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-2.5">
          <span className="relative flex h-2.5 w-2.5">
            <span className="pulse-dot absolute inline-flex h-2.5 w-2.5 rounded-full bg-teal" />
            <span className="relative inline-flex h-2.5 w-2.5 rounded-full bg-teal" />
          </span>
          <div className="leading-tight">
            <p className="text-sm font-semibold text-teal-deep">已连接</p>
            <p className="text-xs text-teal/90">{state.server_name}</p>
          </div>
        </div>
        <Button variant="danger" loading={busy} onClick={disconnect}>
          <Power className="h-4 w-4" /> 断开
        </Button>
      </div>

      <TrafficFlow traffic={traffic} serverName={state.server_name} mode="connected" />

      {/* proxy address */}
      <div>
        <p className="mb-1.5 text-xs font-semibold uppercase tracking-wide text-ink-faint">
          代理地址
        </p>
        <div className="flex items-center gap-2">
          <code className="flex-1 rounded-xl border border-cream-400 bg-cream-200 px-3.5 py-2.5 font-mono text-sm tracking-tight text-ink">
            {proxyAddr}
          </code>
          <button
            onClick={copyProxy}
            className={`flex h-[42px] w-[42px] shrink-0 items-center justify-center rounded-xl border transition ${
              copied
                ? "border-teal/30 bg-teal/10 text-teal-deep"
                : "border-cream-400 bg-cream-50 text-ink-muted hover:border-cream-500 hover:bg-cream-200"
            }`}
            title="复制"
          >
            {copied ? <Check className="h-4 w-4" /> : <Copy className="h-4 w-4" />}
          </button>
        </div>
        <p className="mt-2 text-xs text-ink-faint">
          HTTP / SOCKS5 混合端口，用 <code className="rounded bg-cream-300 px-1 py-0.5 font-mono text-[11px] text-ink-muted">socks5h://</code> 让 DNS 也走隧道。
        </p>
      </div>
    </div>
  );
}
