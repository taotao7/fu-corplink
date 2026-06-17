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
      className={`rounded-2xl border border-slate-200 bg-white/80 p-6 shadow-sm backdrop-blur ${className}`}
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
        <span className="mb-1.5 block text-sm font-medium text-slate-600">
          {label}
        </span>
      )}
      <input
        className={`w-full rounded-xl border border-slate-200 bg-white px-3.5 py-2.5 text-sm text-slate-900 placeholder-slate-400 outline-none transition focus:border-blue-400 focus:ring-2 focus:ring-blue-100 ${className}`}
        {...rest}
      />
    </label>
  );
}

type PillTone = "green" | "amber" | "red" | "slate" | "blue";

const pillTones: Record<PillTone, string> = {
  green: "bg-emerald-50 text-emerald-700 ring-emerald-200",
  amber: "bg-amber-50 text-amber-700 ring-amber-200",
  red: "bg-rose-50 text-rose-700 ring-rose-200",
  slate: "bg-slate-100 text-slate-600 ring-slate-200",
  blue: "bg-blue-50 text-blue-700 ring-blue-200",
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
