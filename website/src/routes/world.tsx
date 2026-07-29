import { useEffect, useRef } from "react";

declare global {
  interface Window {
    mountScrollWorld?: (
      el: HTMLElement,
      config: Record<string, unknown>,
    ) => void;
  }
}

const WORLD_CONFIG = {
  brand: { name: "ClawHatch", href: "/" },
  cta: { label: "Scan now", href: "/#cta" },
  hint: "scroll to hatch",
  diveScroll: 1.45,
  connScroll: 0.8,
  crossfade: 0.18,
  atmosphere: true,
  sections: [
    {
      id: "hatch",
      label: "Hatch",
      still: "/scroll-world/stills/00-brand-claw.webp",
      clip: "/scroll-world/vid/01-hatch.mp4",
      clipMobile: "/scroll-world/vid/01-hatch-m.mp4",
      scroll: 1.7,
      linger: 0.4,
      accent: "#c41e3a",
      eyebrow: "OpenClaw, born secure",
      title: "Your agent is hatching.",
      body: "Real shell access, channels, and keys land in the first hours of life.",
      tags: ["Brand mark", "Local-first", "No account"],
    },
    {
      id: "exposed",
      label: "Exposed",
      still: "/scroll-world/stills/02-exposed.webp",
      clip: "/scroll-world/vid/02-exposed.mp4",
      clipMobile: "/scroll-world/vid/02-exposed-m.mp4",
      accent: "#e05a3c",
      eyebrow: "Working ≠ safe",
      title: "Most births are already exposed.",
      body: "Open DMs, gateway on the network, keys on disk — the config works and still burns you.",
      tags: ["Open gateway", "Keys in json", "No allowlist"],
    },
    {
      id: "scan",
      label: "Scan",
      still: "/scroll-world/stills/03-scan.webp",
      clip: "/scroll-world/vid/03-scan.mp4",
      clipMobile: "/scroll-world/vid/03-scan-m.mp4",
      accent: "#3db8c9",
      eyebrow: "One command",
      title: "Score it. Fix what you can.",
      body: "npx clawhatch scan runs 100+ OpenClaw-aware checks and prints a 0–100 score on your machine.",
      tags: ["Under 1s", "Offline", "--fix"],
    },
    {
      id: "identity",
      label: "Identity",
      still: "/scroll-world/stills/04-identity.webp",
      clip: "/scroll-world/vid/04-identity.mp4",
      clipMobile: "/scroll-world/vid/04-identity-m.mp4",
      accent: "#3d9b6a",
      eyebrow: "Identity first",
      title: "Who can trigger beats the model.",
      body: "Strict allowlists and pairing before tools and sandboxes. Action second. Model last.",
      tags: ["dmPolicy", "allowFrom", "Pairing"],
    },
    {
      id: "nest",
      label: "Nest",
      still: "/scroll-world/stills/05-nest.webp",
      clip: "/scroll-world/vid/05-nest.mp4",
      clipMobile: "/scroll-world/vid/05-nest-m.mp4",
      scroll: 1.6,
      linger: 0.45,
      accent: "#c41e3a",
      eyebrow: "Stay hatched",
      title: "Born secure. Keep the nest clean.",
      body: "Hatch free forever. Nest when you need continuous posture. Secure Hatch when you want a human.",
      tags: ["Hatch free", "Nest paid", "Proof"],
      cta: {
        primary: { label: "npx clawhatch scan", href: "/#cta" },
        secondary: { label: "Product site", href: "/" },
      },
    },
  ],
  connectors: [null, null, null, null],
};

export function WorldPage() {
  const ref = useRef<HTMLDivElement>(null);

  useEffect(() => {
    let cancelled = false;
    const host = ref.current;
    if (!host) return;

    async function load() {
      if (!window.mountScrollWorld) {
        await new Promise<void>((resolve, reject) => {
          const s = document.createElement("script");
          s.src = "/scroll-world/scrub-engine.js";
          s.async = true;
          s.onload = () => resolve();
          s.onerror = () => reject(new Error("Failed to load scrub-engine"));
          document.body.appendChild(s);
        });
      }
      if (cancelled || !host || !window.mountScrollWorld) return;
      host.innerHTML = "";
      window.mountScrollWorld(host, WORLD_CONFIG);
    }

    load().catch(console.error);
    return () => {
      cancelled = true;
      if (host) host.innerHTML = "";
    };
  }, []);

  return (
    <div className="min-h-svh w-full max-w-[100vw] overflow-x-hidden bg-[#0a0a0c]">
      <div ref={ref} id="world" className="w-full min-w-0" />
    </div>
  );
}
