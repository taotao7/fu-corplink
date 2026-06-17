import { useEffect, useState } from "react";
import { api, formatRate, formatBytes, type State, type Traffic } from "../api";
import { Button } from "../ui/Button";
import { ArrowDown, ArrowUp, Copy, Check, Power, Plug } from "lucide-react";

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

  if (!connected) {
    return (
      <div className="rounded-xl border border-slate-200 bg-slate-50/60 p-4 text-center text-sm text-slate-500">
        <Plug className="mx-auto mb-2 h-5 w-5 text-slate-400" />
        选择一个节点并连接，连接成功后即可使用代理。
      </div>
    );
  }

  const proxyAddr = traffic?.proxy_listen || state.proxy_listen;

  return (
    <div className="space-y-4">
      <div className="rounded-xl border border-emerald-200 bg-emerald-50/50 p-4">
        <div className="mb-3 flex items-center justify-between">
          <span className="text-sm font-medium text-emerald-700">
            已连接 · {state.server_name}
          </span>
          <Button variant="danger" loading={busy} onClick={disconnect}>
            <Power className="h-4 w-4" /> 断开
          </Button>
        </div>
        <div className="grid grid-cols-2 gap-3">
          <RateCard
            icon={<ArrowDown className="h-4 w-4 text-emerald-600" />}
            label="下载"
            rate={traffic ? formatRate(traffic.rx_bps) : "—"}
            total={traffic ? formatBytes(traffic.rx_total) : "—"}
          />
          <RateCard
            icon={<ArrowUp className="h-4 w-4 text-indigo-600" />}
            label="上传"
            rate={traffic ? formatRate(traffic.tx_bps) : "—"}
            total={traffic ? formatBytes(traffic.tx_total) : "—"}
          />
        </div>
      </div>

      <div className="rounded-xl border border-slate-200 bg-white p-4">
        <p className="mb-1.5 text-sm font-medium text-slate-600">代理地址</p>
        <div className="flex items-center gap-2">
          <code className="flex-1 rounded-lg bg-slate-100 px-3 py-2 text-sm text-slate-800">
            {proxyAddr}
          </code>
          <button
            onClick={copyProxy}
            className="rounded-lg border border-slate-200 p-2 text-slate-500 transition hover:bg-slate-50"
            title="复制"
          >
            {copied ? (
              <Check className="h-4 w-4 text-emerald-600" />
            ) : (
              <Copy className="h-4 w-4" />
            )}
          </button>
        </div>
        <p className="mt-2 text-xs text-slate-400">
          HTTP / SOCKS5 混合端口，用 <code>socks5h://</code> 让 DNS 也走隧道。
        </p>
      </div>
    </div>
  );
}

function RateCard({
  icon,
  label,
  rate,
  total,
}: {
  icon: React.ReactNode;
  label: string;
  rate: string;
  total: string;
}) {
  return (
    <div className="rounded-lg bg-white/70 px-3 py-2">
      <div className="flex items-center gap-1.5 text-xs text-slate-500">
        {icon} {label}
      </div>
      <p className="mt-0.5 text-lg font-semibold tabular-nums text-slate-800">{rate}</p>
      <p className="text-xs text-slate-400">累计 {total}</p>
    </div>
  );
}
