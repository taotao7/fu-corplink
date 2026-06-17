import { type ReactNode, type ButtonHTMLAttributes } from "react";

type Variant = "primary" | "secondary" | "ghost" | "danger";
type Size = "sm" | "md";

const styles: Record<Variant, string> = {
  primary:
    "bg-gradient-to-b from-burnt to-burnt-soft text-cream-50 hover:from-burnt hover:to-burnt active:to-rust shadow-[0_1px_2px_rgba(214,93,14,0.4),0_8px_20px_-8px_rgba(214,93,14,0.6)]",
  secondary:
    "bg-cream-50 text-ink border border-cream-400 hover:bg-cream-200 hover:border-cream-500 shadow-sm",
  ghost: "text-ink-muted hover:bg-cream-200 hover:text-ink",
  danger:
    "bg-cream-50 text-rust border border-rust/30 hover:bg-rust/5 hover:border-rust/50 shadow-sm",
};

const sizes: Record<Size, string> = {
  sm: "px-3 py-1.5 text-sm rounded-lg",
  md: "px-4 py-2.5 text-sm rounded-xl",
};

interface Props extends ButtonHTMLAttributes<HTMLButtonElement> {
  variant?: Variant;
  size?: Size;
  loading?: boolean;
  children: ReactNode;
}

export function Button({
  variant = "primary",
  size = "md",
  loading,
  children,
  className = "",
  disabled,
  ...rest
}: Props) {
  return (
    <button
      className={`inline-flex items-center justify-center gap-2 font-medium transition-all duration-150 active:scale-[0.98] disabled:pointer-events-none disabled:opacity-50 ${sizes[size]} ${styles[variant]} ${className}`}
      disabled={disabled || loading}
      {...rest}
    >
      {loading && (
        <span className="h-4 w-4 animate-spin rounded-full border-2 border-current border-t-transparent" />
      )}
      {children}
    </button>
  );
}
