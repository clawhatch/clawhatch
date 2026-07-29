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

## Current deployment

The verified static build is published from the repository's `gh-pages`
branch.

- Temporary live URL: `https://clawhatch.github.io/clawhatch/`
- Canonical URL after the registrar cut-over: `https://clawhatch.co.uk`
- DNS instructions: `public/dns-setup.md`

The temporary Pages build uses the `/clawhatch/` base path. The
custom-domain-ready build is retained in the `gh-pages` history and uses `/`.

## Vercel (supported alternative)

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
4. At **names.co.uk** DNS, set the exact **A / CNAME values Vercel shows**
5. Do **not** change nameservers or MX if you use names.co.uk email

Canonical URL: **https://clawhatch.co.uk**

## Routes

| Path | Content |
|------|---------|
| `/` | Landing (hero, features, how-it-works, pricing, signup, footer) |
| `/world` | Scroll-scrubbed ClawHatch world (video + copy) |
| `/scroll-world/` | Standalone scroll-world HTML (same assets) |

Assets: `/claw-hero.jpeg`, `/scroll-world/stills/*`, `/scroll-world/vid/*`

## Payments

The pricing CTAs accept public hosted-checkout URLs at build time:

```bash
VITE_NEST_CHECKOUT_URL=https://checkout.example/nest
VITE_SECURE_HATCH_CHECKOUT_URL=https://checkout.example/secure-hatch
```

If a URL is absent, the corresponding card uses the honest email/contact path.
Do not add a checkout URL until the payment account is verified and the product
name, currency, price, tax treatment, refund terms, and fulfilment are approved.

## Source of truth

Product claims (version, check counts, freemium) live in `src/lib/product.ts` and should track the CLI README on GitHub.
