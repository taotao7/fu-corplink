import { useEffect, useState } from "react";
import { api, type ConfigView } from "../api";
import { Dialog } from "../ui/Dialog";
import { Input } from "../ui/Card";
import { Button } from "../ui/Button";

export function SettingsDialog({
  open,
  onClose,
}: {
  open: boolean;
  onClose: () => void;
}) {
  const [cfg, setCfg] = useState<ConfigView | null>(null);
  const [saving, setSaving] = useState(false);

  useEffect(() => {
    if (open) api.getConfig().then(setCfg).catch(() => {});
  }, [open]);

  async function save() {
    if (!cfg) return;
    setSaving(true);
    try {
      await api.putConfig({
        socks_listen: cfg.socks_listen,
        vpn_select_strategy: cfg.vpn_select_strategy,
        route_mode: cfg.route_mode,
        force_protocol: cfg.force_protocol,
      });
      onClose();
    } finally {
      setSaving(false);
    }
  }

  return (
    <Dialog open={open} onClose={onClose} title="设置">
      {cfg && (
        <div className="space-y-4">
          <Input
            label="代理监听地址 (socks_listen)"
            value={cfg.socks_listen}
            onChange={(e) => setCfg({ ...cfg, socks_listen: e.target.value })}
          />
          <Select
            label="节点选择策略"
            value={cfg.vpn_select_strategy}
            onChange={(v) => setCfg({ ...cfg, vpn_select_strategy: v })}
            options={[
              { value: "default", label: "默认（首个可达）" },
              { value: "latency", label: "最低延迟" },
            ]}
          />
          <Select
            label="路由模式"
            value={cfg.route_mode}
            onChange={(v) => setCfg({ ...cfg, route_mode: v })}
            options={[
              { value: "full", label: "全局 (full)" },
              { value: "split", label: "分流 (split)" },
            ]}
          />
          <Select
            label="WireGuard 协议"
            value={cfg.force_protocol}
            onChange={(v) => setCfg({ ...cfg, force_protocol: v })}
            options={[
              { value: "", label: "自动 (protocol_mode)" },
              { value: "udp", label: "强制 UDP" },
              { value: "tcp", label: "强制 TCP" },
            ]}
          />
          <p className="text-xs text-ink-faint">代理地址改动会在下次连接时生效。</p>
          <div className="flex justify-end gap-2">
            <Button variant="secondary" onClick={onClose}>
              取消
            </Button>
            <Button onClick={save} loading={saving}>
              保存
            </Button>
          </div>
        </div>
      )}
    </Dialog>
  );
}

function Select({
  label,
  value,
  onChange,
  options,
}: {
  label: string;
  value: string;
  onChange: (v: string) => void;
  options: { value: string; label: string }[];
}) {
  return (
    <label className="block">
      <span className="mb-1.5 block text-sm font-medium text-ink-muted">{label}</span>
      <select
        value={value}
        onChange={(e) => onChange(e.target.value)}
        className="w-full rounded-xl border border-cream-400 bg-cream-50 px-3.5 py-2.5 text-sm outline-none focus:border-burnt focus:ring-2 focus:ring-burnt/15"
      >
        {options.map((o) => (
          <option key={o.value} value={o.value}>
            {o.label}
          </option>
        ))}
      </select>
    </label>
  );
}
