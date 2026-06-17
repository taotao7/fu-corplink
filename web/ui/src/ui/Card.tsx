import { type ReactNode, type InputHTMLAttributes } from "react";

export function Card({
  children,
  className = "",
}: {
  children: ReactNode;
  className?: string;
}) {
  return (
    <div
      className={`rounded-3xl border border-cream-300 bg-cream-50/90 p-6 shadow-[0_1px_2px_rgba(45,42,39,0.04),0_12px_32px_-14px_rgba(45,42,39,0.22)] ring-1 ring-ink/[0.03] backdrop-blur-xl ${className}`}
    >
      {children}
    </div>
  );
}

interface InputProps extends InputHTMLAttributes<HTMLInputElement> {
  label?: string;
}

export function Input({ label, className = "", ...rest }: InputProps) {
  return (
    <label className="block">
      {label && (
        <span className="mb-1.5 block text-sm font-medium text-ink-muted">
          {label}
        </span>
      )}
      <input
        className={`w-full rounded-xl border border-cream-400 bg-cream-50 px-3.5 py-2.5 text-sm text-ink placeholder-ink-faint shadow-sm outline-none transition focus:border-burnt focus:ring-2 focus:ring-burnt/15 ${className}`}
        {...rest}
      />
    </label>
  );
}

type PillTone = "green" | "amber" | "red" | "slate" | "blue";

const pillTones: Record<PillTone, string> = {
  green: "bg-teal/10 text-teal-deep ring-teal/30",
  amber: "bg-burnt/10 text-burnt ring-burnt/30",
  red: "bg-rust/10 text-rust ring-rust/30",
  slate: "bg-cream-300 text-ink-muted ring-cream-500",
  blue: "bg-teal/10 text-teal-deep ring-teal/30",
};

export function Pill({
  tone = "slate",
  children,
}: {
  tone?: PillTone;
  children: ReactNode;
}) {
  return (
    <span
      className={`inline-flex items-center gap-1.5 rounded-full px-2.5 py-1 text-xs font-medium ring-1 ring-inset ${pillTones[tone]}`}
    >
      {children}
    </span>
  );
}
