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
          <Search className="absolute left-3 top-1/2 h-4 w-4 -translate-y-1/2 text-ink-faint" />
          <input
            value={query}
            onChange={(e) => setQuery(e.target.value)}
            placeholder="搜索节点"
            className="w-full rounded-xl border border-cream-400 bg-cream-50 py-2.5 pl-9 pr-3 text-sm shadow-sm outline-none focus:border-burnt focus:ring-2 focus:ring-burnt/15"
          />
        </div>
        <button
          onClick={onRefresh}
          disabled={loading}
          className="flex h-[42px] w-[42px] shrink-0 items-center justify-center rounded-xl border border-cream-400 bg-cream-50 text-ink-muted shadow-sm transition hover:border-cream-500 hover:bg-cream-200 disabled:opacity-50"
          title="重新探测延迟"
        >
          <RefreshCw className={`h-4 w-4 ${loading ? "animate-spin" : ""}`} />
        </button>
      </div>

      <div className="scroll-thin max-h-[22rem] space-y-2 overflow-y-auto pr-1">
        {filtered.length === 0 && (
          <p className="py-8 text-center text-sm text-ink-faint">
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
                  ? "border-burnt/40 bg-burnt/5 ring-1 ring-burnt/20"
                  : "border-cream-300 bg-cream-50 hover:border-burnt/30 hover:bg-cream-200"
              }`}
            >
              <div className="flex min-w-0 items-center gap-2.5">
                <span
                  className={`flex h-4 w-4 shrink-0 items-center justify-center rounded-full border ${
                    pinned ? "border-burnt bg-burnt" : "border-cream-500"
                  }`}
                >
                  {pinned && <Check className="h-3 w-3 text-cream-50" />}
                </span>
                <div className="min-w-0">
                  <p className="truncate text-sm font-medium text-ink">
                    {s.name || s.en_name}
                  </p>
                  <p className="truncate text-xs text-ink-faint">{s.ip}</p>
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
                    className="rounded-lg p-1.5 text-burnt transition hover:bg-burnt/10"
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
