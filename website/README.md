# ClawHatch website

Marketing site for **[clawhatch.co.uk](https://clawhatch.co.uk)** — the public face of the [clawhatch/clawhatch](https://github.com/clawhatch/clawhatch) OpenClaw security scanner.

Lives in the monorepo at **`website/`** so the **repository root `package.json` stays the CLI package** (`npx clawhatch scan`).

## Stack

- React 19 + TypeScript
- Vite 8 static build
- Tailwind CSS v4
- Portable scroll-world engine under `/world` and `/scroll-world/`

## Local

```bash
cd website
npm install
npm run dev      # http://127.0.0.1:8080
npm run build
npm run typecheck
```

## Vercel (exact settings)

| Setting | Value |
|---------|--------|
| **Root Directory** | `website` |
| **Framework Preset** | Vite (or Other) |
| **Build Command** | `npm run build` |
| **Install Command** | `npm ci` |
| **Output Directory** | `dist` |
| **Node** | 22.x |

### Domains

1. Project → **Settings → Domains**
2. Add `clawhatch.co.uk` and `www.clawhatch.co.uk`
3. Prefer **redirect www → apex**
4. At **names.co.uk** DNS, set the **A / CNAME values Vercel shows** (typical: apex `A` → `76.76.21.21`, `www` CNAME → `cname.vercel-dns.com`)
5. Do **not** change nameservers or MX if you use names.co.uk email

Canonical URL: **https://clawhatch.co.uk**

## Routes

| Path | Content |
|------|---------|
| `/` | Landing (hero, features, how-it-works, pricing, signup, footer) |
| `/world` | Scroll-scrubbed ClawHatch world (video + copy) |
| `/scroll-world/` | Standalone scroll-world HTML (same assets) |

Assets: `/claw-hero.jpeg`, `/scroll-world/stills/*`, `/scroll-world/vid/*`

## Source of truth

Product claims (version, check counts, freemium) live in `src/lib/product.ts` and should track the CLI README on GitHub.
