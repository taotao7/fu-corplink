import { type State } from "../api";
import { Pill } from "../ui/Card";
import { ShieldCheck, Wifi, WifiOff } from "lucide-react";

function statusPill(state: State["state"]) {
  switch (state) {
    case "connected":
      return (
        <Pill tone="green">
          <Wifi className="h-3.5 w-3.5" /> 已连接
        </Pill>
      );
    case "connecting":
      return (
        <Pill tone="amber">
          <Wifi className="h-3.5 w-3.5" /> 连接中
        </Pill>
      );
    case "disconnecting":
      return (
        <Pill tone="amber">
          <WifiOff className="h-3.5 w-3.5" /> 断开中
        </Pill>
      );
    case "logged_in":
      return (
        <Pill tone="blue">
          <WifiOff className="h-3.5 w-3.5" /> 未连接
        </Pill>
      );
    default:
      return (
        <Pill tone="slate">
          <WifiOff className="h-3.5 w-3.5" /> 未登录
        </Pill>
      );
  }
}

export function Header({ state }: { state: State | null }) {
  return (
    <header className="mb-8 flex items-center justify-between">
      <div className="flex items-center gap-3">
        <img src="/logo.png" alt="logo" className="h-9 w-9 rounded-xl" />
        <div>
          <h1 className="flex items-center gap-1.5 text-lg font-semibold text-slate-900">
            CorpLink Web
            <ShieldCheck className="h-4 w-4 text-blue-500" />
          </h1>
          {state?.company_name && (
            <p className="text-xs text-slate-500">{state.company_name}</p>
          )}
        </div>
      </div>
      {state && statusPill(state.state)}
    </header>
  );
}
