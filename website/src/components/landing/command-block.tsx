import { useState } from "react";
import { Check, Copy, Terminal } from "lucide-react";
import { cn } from "@/lib/utils";
import { PRODUCT } from "@/lib/product";

const COMMAND = PRODUCT.primaryCommand;

export function CommandBlock({ className }: { className?: string }) {
  const [copied, setCopied] = useState(false);

  async function copy() {
    try {
      await navigator.clipboard.writeText(COMMAND);
      setCopied(true);
      window.setTimeout(() => setCopied(false), 1800);
    } catch {
      /* clipboard may be blocked */
    }
  }

  return (
    <div
      className={cn(
        "group relative flex w-full max-w-xl items-center gap-3 overflow-hidden rounded-lg border border-border bg-elevated p-1 pl-4 shadow-lg shadow-black/40",
        className,
      )}
    >
      <Terminal className="h-4 w-4 shrink-0 text-subtle" aria-hidden />
      <code className="min-w-0 flex-1 truncate font-mono text-sm text-fg sm:text-base">
        {COMMAND}
      </code>
      <button
        type="button"
        onClick={copy}
        className="inline-flex h-10 shrink-0 items-center gap-2 rounded-md bg-primary px-4 text-sm font-medium text-primary-fg transition-colors hover:bg-primary-hover"
      >
        {copied ? (
          <>
            <Check className="h-4 w-4" />
            Copied
          </>
        ) : (
          <>
            <Copy className="h-4 w-4" />
            Copy
          </>
        )}
      </button>
    </div>
  );
}
