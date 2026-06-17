import { type State } from "../api";
import { ShieldCheck, Wifi, WifiOff } from "lucide-react";

function statusPill(state: State["state"]) {
  switch (state) {
    case "connected":
      return (
        <span className="inline-flex items-center gap-2 rounded-full border border-teal/30 bg-teal/10 px-3 py-1.5 text-xs font-semibold text-teal-deep shadow-sm backdrop-blur">
          <span className="relative flex h-2 w-2">
            <span className="pulse-dot absolute inline-flex h-2 w-2 rounded-full bg-teal" />
            <span className="relative inline-flex h-2 w-2 rounded-full bg-teal" />
          </span>
          已连接
        </span>
      );
    case "connecting":
      return (
        <span className="inline-flex items-center gap-2 rounded-full border border-burnt/30 bg-burnt/10 px-3 py-1.5 text-xs font-semibold text-burnt shadow-sm backdrop-blur">
          <Wifi className="h-3.5 w-3.5 animate-pulse" /> 连接中
        </span>
      );
    case "disconnecting":
      return (
        <span className="inline-flex items-center gap-2 rounded-full border border-burnt/30 bg-burnt/10 px-3 py-1.5 text-xs font-semibold text-burnt shadow-sm backdrop-blur">
          <WifiOff className="h-3.5 w-3.5 animate-pulse" /> 断开中
        </span>
      );
    case "logged_in":
      return (
        <span className="inline-flex items-center gap-2 rounded-full border border-cream-400 bg-cream-50/70 px-3 py-1.5 text-xs font-semibold text-ink-muted shadow-sm backdrop-blur">
          <span className="h-2 w-2 rounded-full bg-cream-500" /> 未连接
        </span>
      );
    default:
      return (
        <span className="inline-flex items-center gap-2 rounded-full border border-cream-400 bg-cream-50/70 px-3 py-1.5 text-xs font-semibold text-ink-faint shadow-sm backdrop-blur">
          <span className="h-2 w-2 rounded-full bg-cream-500" /> 未登录
        </span>
      );
  }
}

export function Header({ state }: { state: State | null }) {
  return (
    <header className="mb-8 flex items-center justify-between">
      <div className="flex items-center gap-3">
        <div className="relative flex h-11 w-11 items-center justify-center rounded-2xl bg-gradient-to-br from-burnt to-rust shadow-[0_4px_14px_-2px_rgba(214,93,14,0.5)]">
          <ShieldCheck className="h-6 w-6 text-cream-50" strokeWidth={2.2} />
          <span className="absolute inset-0 rounded-2xl ring-1 ring-inset ring-white/25" />
        </div>
        <div>
          <h1 className="text-lg font-bold tracking-tight text-ink">
            CorpLink <span className="text-burnt">Web</span>
          </h1>
          {state?.company_name && (
            <p className="text-xs font-medium text-ink-muted">{state.company_name}</p>
          )}
        </div>
      </div>
      {state && statusPill(state.state)}
    </header>
  );
}
