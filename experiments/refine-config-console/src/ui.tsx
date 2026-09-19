// Local shadcn/ui Button and Sheet adaptations; attribution is in NOTICE.md.
import * as Dialog from "@radix-ui/react-dialog";
import { Slot } from "@radix-ui/react-slot";
import { cva, type VariantProps } from "class-variance-authority";
import { clsx, type ClassValue } from "clsx";
import { twMerge } from "tailwind-merge";
import { useEffect, useRef, useState, type ComponentProps, type ReactNode } from "react";
import { Icon } from "./icons";

export const cn = (...inputs: ClassValue[]) => twMerge(clsx(inputs));
const buttonVariants = cva("ui-button", {
  variants: { variant: { default: "button-primary", outline: "button-outline" } },
  defaultVariants: { variant: "default" },
});
export function Button({ className, variant, asChild = false, ...props }:
  ComponentProps<"button"> & VariantProps<typeof buttonVariants> & { asChild?: boolean }) {
  const Comp = asChild ? Slot : "button";
  return <Comp className={cn(buttonVariants({ variant, className }))} {...props} />;
}
declare global {
  interface Window { configConsoleTheme?: { set: (value: "light" | "dark") => void } }
}
export function ThemeToggle() {
  const [dark, setDark] = useState(() => document.documentElement.dataset.theme === "dark");
  useEffect(() => {
    const sync = () => setDark(document.documentElement.dataset.theme === "dark");
    window.addEventListener("config-theme-change", sync);
    sync();
    return () => window.removeEventListener("config-theme-change", sync);
  }, []);
  return <Button type="button" variant="outline" aria-label="Dark mode" aria-pressed={dark}
    title={dark ? "Switch to light mode" : "Switch to dark mode"}
    disabled={!window.configConsoleTheme}
    onClick={() => window.configConsoleTheme?.set(dark ? "light" : "dark")}>
    <Icon name={dark ? "moon" : "sun"} /><span>Dark mode</span>
    <span className="theme-state" aria-hidden="true">{dark ? "On" : "Off"}</span>
  </Button>;
}
export function Sheet({ open, onOpenChange, title, children, eyebrow = "Control details",
  description = "Read-only AWS Config evidence. No remediation action is available.", closeLabel = "Close details" }: {
  open: boolean; onOpenChange: (value: boolean) => void; title: string; children: ReactNode;
  eyebrow?: string; description?: string; closeLabel?: string;
}) {
  const previousFocus = useRef<HTMLElement | null>(null);
  return <Dialog.Root open={open} onOpenChange={onOpenChange}>
    <Dialog.Portal>
      <Dialog.Overlay className="sheet-overlay" />
      <Dialog.Content className="sheet-content"
        onOpenAutoFocus={() => { previousFocus.current = document.activeElement instanceof HTMLElement ? document.activeElement : null; }}
        onCloseAutoFocus={(event) => {
          event.preventDefault();
          const target = previousFocus.current?.isConnected ? previousFocus.current : document.getElementById("main-content");
          target?.focus({ preventScroll: true });
        }}>
        <header className="sheet-header">
          <div><div className="eyebrow">{eyebrow}</div>
            <Dialog.Title className="sheet-title">{title}</Dialog.Title></div>
          <Dialog.Close asChild><Button variant="outline" aria-label={closeLabel}>
            <Icon name="close" /><span>Close</span>
          </Button></Dialog.Close>
        </header>
        <Dialog.Description className="muted sheet-description">
          {description}
        </Dialog.Description>
        {children}
      </Dialog.Content>
    </Dialog.Portal>
  </Dialog.Root>;
}
