import { useMemo } from "react";
import { formatRate, formatBytes, type Traffic } from "../api";

// Circuit-board geometry (SVG user units, viewBox 0 0 360 130).
// Both traces are drawn left->right so that offset-distance 0% = local (left)
// and 100% = peer (right). Download (RX) runs peer->local so its packets use
// animation-direction: reverse; upload (TX) runs local->peer so its packets
// travel forward. The two traces share a symmetric right-angle route with the
// horizontal run offset to the top (RX) and bottom (TX) for a real-PCB look.
const PATH_RX = "M 20,48 L 50,48 L 50,32 L 310,32 L 310,48 L 340,48";
const PATH_TX = "M 20,82 L 50,82 L 50,98 L 310,98 L 310,82 L 340,82";

// x positions of stale-link markers along the horizontal run.
const STALE_X = [110, 175, 240];
const RX_Y = 32;
const TX_Y = 98;

type Mode = "connected" | "connecting";

interface FlowTier {
  dur: number; // seconds for one dash cycle
  packets: number; // bright packet pulses per trace
}

function flowTier(bps: number): FlowTier {
  if (bps < 1) return { dur: 3.2, packets: 0 };
  if (bps < 50_000) return { dur: 1.6, packets: 1 };
  if (bps < 500_000) return { dur: 0.9, packets: 2 };
  if (bps < 5_000_000) return { dur: 0.55, packets: 3 };
  return { dur: 0.34, packets: 4 };
}

function stalenessColor(pct: number): string {
  if (pct <= 0) return "var(--color-teal)";
  if (pct < 15) return "var(--color-olive)";
  if (pct < 50) return "var(--color-burnt)";
  return "var(--color-rust)";
}

function formatHandshakeAge(age: number): string {
  if (age < 0) return "无握手";
  if (age <= 1) return "刚刚";
  return `${age}s 前`;
}

function clampPct(pct: number): number {
  return Math.max(0, Math.min(100, pct));
}

function truncate(name: string, n: number): string {
  const s = name.trim();
  return s.length <= n ? s : s.slice(0, n - 1) + "…";
}

export function TrafficFlow({
  traffic,
  serverName,
  mode,
}: {
  traffic: Traffic | null;
  serverName: string;
  mode: Mode;
}) {
  const rx = traffic?.rx_bps ?? 0;
  const tx = traffic?.tx_bps ?? 0;
  const staleness = clampPct(traffic?.handshake_stale_pct ?? traffic?.loss_pct ?? 0);
  const age = traffic?.handshake_age_sec ?? -1;
  const linkLabel = age < 0 ? "无握手" : staleness >= 100 ? "异常" : "正常";

  const tierRx = useMemo(() => flowTier(rx), [rx]);
  const tierTx = useMemo(() => flowTier(tx), [tx]);

  const dead = mode === "connected" && staleness >= 100;
  const establishing = mode === "connecting";

  // Packet visibility fades as handshake staleness rises; at 100% the trace is dead.
  const packetAlpha = dead ? 0 : Math.max(0.15, 1 - staleness / 100);
  // Flow dash opacity dims with staleness but keeps a faint keepalive shimmer.
  const flowAlpha = dead ? 0 : Math.max(0.25, 1 - staleness / 130);

  // Number of stale-link markers to show, scaling with handshake staleness.
  const staleMarkerCount = dead ? STALE_X.length : Math.round((staleness / 100) * STALE_X.length);

  return (
    <div className="space-y-3">
      <div className="relative overflow-hidden rounded-2xl border border-cream-400 bg-cream-100/70 p-2">
        <CircuitGrid />
        <svg
          viewBox="0 0 360 130"
          className="relative w-full"
          role="img"
          aria-label={`下载 ${formatRate(rx)}，上传 ${formatRate(tx)}，链路 ${linkLabel}，握手 ${formatHandshakeAge(age)}`}
        >
          {/* chips: local (left) and peer (right) */}
          <Chip x={8} label="本机" />
          <Chip x={328} label={truncate(serverName || "对端", 6)} />

          {/* RX (download) trace */}
          <Trace
            path={PATH_RX}
            color="var(--color-teal)"
            mode={mode}
            dead={dead}
            flowDir="rev"
            dur={tierRx.dur}
            flowAlpha={flowAlpha}
          />
          {/* TX (upload) trace */}
          <Trace
            path={PATH_TX}
            color="var(--color-burnt)"
            mode={mode}
            dead={dead}
            flowDir="fwd"
            dur={tierTx.dur}
            flowAlpha={flowAlpha}
          />

          {/* vias at the trace endpoints */}
          <Via x={20} y={48} color="var(--color-teal)" dim={dead} />
          <Via x={340} y={48} color="var(--color-teal)" dim={dead} />
          <Via x={20} y={82} color="var(--color-burnt)" dim={dead} />
          <Via x={340} y={82} color="var(--color-burnt)" dim={dead} />

          {/* direction arrows on the horizontal runs */}
          <Arrow x={180} y={RX_Y} dir="left" color="var(--color-teal-deep)" dim={dead || establishing} />
          <Arrow x={180} y={TX_Y} dir="right" color="var(--color-burnt-soft)" dim={dead || establishing} />

          {/* packet pulses */}
          {!dead && !establishing && (
            <>
              {renderPackets(PATH_RX, "var(--color-teal)", tierRx.packets, tierRx.dur, true, packetAlpha)}
              {renderPackets(PATH_TX, "var(--color-burnt)", tierTx.packets, tierTx.dur, false, packetAlpha)}
            </>
          )}

          {/* stale-link markers */}
          {staleMarkerCount > 0 &&
            STALE_X.slice(0, staleMarkerCount).map((x, i) => (
              <g key={`stale-${i}`} opacity={0.85}>
                <StaleMarker x={x} y={RX_Y} />
                <StaleMarker x={STALE_X[(i + 1) % STALE_X.length]} y={TX_Y} />
              </g>
            ))}
        </svg>

        {/* overlay labels */}
        <div className="pointer-events-none absolute inset-0 flex items-center justify-between px-3 pt-2 text-[10px] font-semibold uppercase tracking-wide">
          <span className="text-teal-deep">↓ 下载</span>
          <span className="text-burnt-soft">上传 ↑</span>
        </div>
      </div>

      {/* readouts + link-health badge */}
      <div className="grid grid-cols-3 gap-2">
        <Readout
          label="下载"
          rate={traffic ? formatRate(traffic.rx_bps) : "—"}
          total={traffic ? formatBytes(traffic.rx_total) : "—"}
          color="text-teal-deep"
        />
        <Readout
          label="上传"
          rate={traffic ? formatRate(traffic.tx_bps) : "—"}
          total={traffic ? formatBytes(traffic.tx_total) : "—"}
          color="text-burnt"
        />
        <LinkHealthBadge staleness={staleness} age={age} dead={dead} />
      </div>
    </div>
  );
}

function CircuitGrid() {
  // subtle PCB dot grid as a background pattern
  const dots = [];
  for (let x = 16; x < 360; x += 16) {
    for (let y = 14; y < 130; y += 16) {
      dots.push(`${x},${y}`);
    }
  }
  return (
    <svg viewBox="0 0 360 130" className="absolute inset-0 h-full w-full opacity-[0.35]">
      {dots.map((p, i) => {
        const [x, y] = p.split(",").map(Number);
        return <circle key={i} cx={x} cy={y} r={0.7} fill="var(--color-cream-500)" />;
      })}
    </svg>
  );
}

function Chip({ x, label }: { x: number; label: string }) {
  return (
    <g>
      <rect
        x={x}
        y={26}
        width={24}
        height={78}
        rx={5}
        fill="var(--color-cream-200)"
        stroke="var(--color-cream-500)"
        strokeWidth={1}
      />
      <rect x={x + 3} y={29} width={18} height={72} rx={3} fill="none" stroke="var(--color-cream-400)" strokeWidth={0.6} />
      <text
        x={x + 12}
        y={119}
        textAnchor="middle"
        fontSize={9}
        fontWeight={600}
        fill="var(--color-ink-muted)"
        style={{ fontFamily: "ui-sans-serif, system-ui, sans-serif" }}
      >
        {label}
      </text>
    </g>
  );
}

function Trace({
  path,
  color,
  mode,
  dead,
  flowDir,
  dur,
  flowAlpha,
}: {
  path: string;
  color: string;
  mode: Mode;
  dead: boolean;
  flowDir: "fwd" | "rev";
  dur: number;
  flowAlpha: number;
}) {
  const establishing = mode === "connecting";
  // dead trace turns red and static; establishing blinks softly; otherwise the
  // base trace is static and only the dashed overlay marches.
  const stroke = dead ? "var(--color-rust)" : color;
  const baseOpacity = dead ? 0.4 : establishing ? 0.5 : 0.55;
  const baseClass = establishing ? "blink-soft" : "";
  return (
    <>
      {/* base PCB trace */}
      <path d={path} fill="none" stroke="var(--color-cream-500)" strokeWidth={2.4} opacity={baseOpacity} className={baseClass} />
      {/* colored core */}
      <path d={path} fill="none" stroke={stroke} strokeWidth={1.4} opacity={baseOpacity} className={baseClass} />
      {/* marching dashes = data flow */}
      {!establishing && !dead && (
        <path
          d={path}
          fill="none"
          stroke={stroke}
          strokeWidth={2}
          strokeLinecap="round"
          strokeDasharray="3 17"
          opacity={flowAlpha}
          className={flowDir === "fwd" ? "flow-fwd" : "flow-rev"}
          style={{ animationDuration: `${dur}s` }}
        />
      )}
    </>
  );
}

function Via({ x, y, color, dim }: { x: number; y: number; color: string; dim: boolean }) {
  return (
    <g opacity={dim ? 0.5 : 1}>
      <circle cx={x} cy={y} r={4.5} fill="var(--color-cream-50)" stroke="var(--color-cream-500)" strokeWidth={1} />
      <circle cx={x} cy={y} r={2.4} fill={color} />
    </g>
  );
}

function Arrow({ x, y, dir, color, dim }: { x: number; y: number; dir: "left" | "right"; color: string; dim: boolean }) {
  const s = 3.2;
  const pts = dir === "right" ? `${x - s},${y - s} ${x + s},${y} ${x - s},${y + s}` : `${x + s},${y - s} ${x - s},${y} ${x + s},${y + s}`;
  return <polygon points={pts} fill={color} opacity={dim ? 0.25 : 0.7} />;
}

function StaleMarker({ x, y }: { x: number; y: number }) {
  return (
    <g stroke="var(--color-rust)" strokeWidth={1.4} strokeLinecap="round" opacity={0.9}>
      <line x1={x - 3} y1={y - 3} x2={x + 3} y2={y + 3} />
      <line x1={x - 3} y1={y + 3} x2={x + 3} y2={y - 3} />
    </g>
  );
}

function renderPackets(
  path: string,
  color: string,
  count: number,
  dur: number,
  reverse: boolean,
  alpha: number
) {
  const items = [];
  for (let i = 0; i < count; i++) {
    const delay = (dur / count) * i;
    items.push(
      <circle
        key={`pkt-${path}-${i}`}
        r={3}
        cx={0}
        cy={0}
        fill={color}
        className="packet"
        opacity={alpha}
        style={{
          offsetPath: `path("${path}")`,
          offsetDistance: "0%",
          animationDuration: `${dur}s`,
          animationDelay: `-${delay}s`,
          animationDirection: reverse ? "reverse" : "normal",
        }}
      />
    );
    // trailing glow
    items.push(
      <circle
        key={`glow-${path}-${i}`}
        r={6}
        cx={0}
        cy={0}
        fill={color}
        opacity={alpha * 0.25}
        className="packet"
        style={{
          offsetPath: `path("${path}")`,
          offsetDistance: "0%",
          animationDuration: `${dur}s`,
          animationDelay: `-${delay}s`,
          animationDirection: reverse ? "reverse" : "normal",
        }}
      />
    );
  }
  return items;
}

function Readout({ label, rate, total, color }: { label: string; rate: string; total: string; color: string }) {
  return (
    <div className="rounded-xl border border-cream-400 bg-cream-50 px-2.5 py-2">
      <p className="text-[10px] font-semibold uppercase tracking-wide text-ink-faint">{label}</p>
      <p className={`mt-0.5 text-base font-bold tabular-nums tracking-tight ${color}`}>{rate}</p>
      <p className="mt-0.5 text-[10px] text-ink-faint">累计 {total}</p>
    </div>
  );
}

function LinkHealthBadge({ staleness, age, dead }: { staleness: number; age: number; dead: boolean }) {
  const color = age < 0 ? "var(--color-ink-faint)" : stalenessColor(staleness);
  const label = age < 0 ? "无握手" : dead || staleness >= 100 ? "异常" : "正常";
  const screenReaderLabel = age < 0 ? "尚无握手" : dead || staleness >= 100 ? "链路异常" : "链路正常";
  const ageText = formatHandshakeAge(age);
  return (
    <div
      className="flex flex-col justify-between rounded-xl border px-2.5 py-2"
      style={{ borderColor: `color-mix(in srgb, ${color} 40%, transparent)`, backgroundColor: `color-mix(in srgb, ${color} 10%, transparent)` }}
    >
      <p className="text-[10px] font-semibold uppercase tracking-wide text-ink-faint">链路</p>
      <p className="mt-0.5 text-base font-bold tabular-nums tracking-tight" style={{ color }}>
        {label}
      </p>
      <p className="mt-0.5 text-[10px] text-ink-faint">握手 {ageText}</p>
      <p className="sr-only">{screenReaderLabel}</p>
    </div>
  );
}
