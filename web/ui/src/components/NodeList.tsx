import { useMemo, useState } from "react";
import { type Server } from "../api";
import { Pill } from "../ui/Card";
import { Pin, Check, Search, RefreshCw } from "lucide-react";

function latencyTone(ms: number): "green" | "amber" | "red" | "slate" {
  if (ms < 0) return "red";
  if (ms === 0) return "slate";
  if (ms < 60) return "green";
  if (ms < 150) return "amber";
  return "red";
}

function latencyText(ms: number): string {
  if (ms < 0) return "超时";
  if (ms === 0) return "—";
  return `${ms}ms`;
}

export function NodeList({
  servers,
  pinnedId,
  loading,
  onPin,
  onRefresh,
}: {
  servers: Server[];
  pinnedId: number;
  loading: boolean;
  onPin: (id: number) => void;
  onRefresh: () => void;
}) {
  const [query, setQuery] = useState("");

  const filtered = useMemo(() => {
    const q = query.trim().toLowerCase();
    if (!q) return servers;
    return servers.filter(
      (s) =>
        s.name.toLowerCase().includes(q) || s.en_name.toLowerCase().includes(q)
    );
  }, [servers, query]);

  return (
    <div>
      <div className="mb-3 flex items-center gap-2">
        <div className="relative flex-1">
          <Search className="absolute left-3 top-1/2 h-4 w-4 -translate-y-1/2 text-slate-400" />
          <input
            value={query}
            onChange={(e) => setQuery(e.target.value)}
            placeholder="搜索节点"
            className="w-full rounded-xl border border-slate-200 bg-white py-2 pl-9 pr-3 text-sm outline-none focus:border-blue-400 focus:ring-2 focus:ring-blue-100"
          />
        </div>
        <button
          onClick={onRefresh}
          disabled={loading}
          className="rounded-xl border border-slate-200 bg-white p-2.5 text-slate-500 transition hover:bg-slate-50 disabled:opacity-50"
          title="重新探测延迟"
        >
          <RefreshCw className={`h-4 w-4 ${loading ? "animate-spin" : ""}`} />
        </button>
      </div>

      <div className="scroll-thin max-h-[22rem] space-y-2 overflow-y-auto pr-1">
        {filtered.length === 0 && (
          <p className="py-8 text-center text-sm text-slate-400">
            {loading ? "正在加载节点…" : "没有匹配的节点"}
          </p>
        )}
        {filtered.map((s) => {
          const pinned = s.id === pinnedId;
          return (
            <div
              key={s.id}
              role="button"
              tabIndex={0}
              onClick={() => onPin(pinned ? 0 : s.id)}
              onKeyDown={(e) =>
                (e.key === "Enter" || e.key === " ") && onPin(pinned ? 0 : s.id)
              }
              className={`flex cursor-pointer items-center justify-between rounded-xl border px-4 py-3 transition ${
                pinned
                  ? "border-blue-300 bg-blue-50 ring-1 ring-blue-200"
                  : "border-slate-200 bg-white hover:border-blue-200 hover:bg-slate-50"
              }`}
            >
              <div className="flex min-w-0 items-center gap-2.5">
                <span
                  className={`flex h-4 w-4 shrink-0 items-center justify-center rounded-full border ${
                    pinned ? "border-blue-500 bg-blue-500" : "border-slate-300"
                  }`}
                >
                  {pinned && <Check className="h-3 w-3 text-white" />}
                </span>
                <div className="min-w-0">
                  <p className="truncate text-sm font-medium text-slate-800">
                    {s.name || s.en_name}
                  </p>
                  <p className="truncate text-xs text-slate-400">{s.ip}</p>
                </div>
              </div>
              <div className="flex items-center gap-3">
                <Pill tone={latencyTone(s.latency_ms)}>{latencyText(s.latency_ms)}</Pill>
                {pinned && (
                  <button
                    onClick={(e) => {
                      e.stopPropagation();
                      onPin(0);
                    }}
                    className="rounded-lg p-1.5 text-blue-600 transition hover:bg-blue-100"
                    title="取消选择"
                  >
                    <Pin className="h-4 w-4" />
                  </button>
                )}
              </div>
            </div>
          );
        })}
      </div>
    </div>
  );
}
