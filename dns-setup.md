# Point clawhatch.co.uk + GitHub at names.co.uk

## Important

Today **clawhatch.co.uk** only shows the names.co.uk **parked-domain** page
(`https://www.names.co.uk/parked-domains/...`). That is **not** the ClawHatch product site.

Goal:
1. Host a real site under names.co.uk (hosting / Site Builder / or upload).
2. DNS already uses names.co.uk nameservers (`ns0/1/2.phase8.net`) — keep them.
3. Point GitHub “Website” / homepage to `https://clawhatch.co.uk`.

---

## A. names.co.uk control panel — make a real site

1. Log in: https://account.names.co.uk (or login.names.co.uk)
2. Open **clawhatch.co.uk**
3. Either:
   - **Enable hosting / Site Builder** on this domain (if included or purchased), **or**
   - Attach an existing **Web hosting** package to this domain
4. In hosting/Site Builder, publish content (or upload `index.html` etc. via File Manager / FTP)
5. Turn **off** “parked domain” / temporary forward if a toggle exists

### DNS for names.co.uk **own** hosting (typical)

Stay on phase8 nameservers. In **DNS management** for clawhatch.co.uk:

| Type | Host | Value | Notes |
|------|------|--------|--------|
| **A** | `@` | IP from your **hosting package** (control panel) | Common shared IPs (confirm in panel): Linux Apache often `85.233.160.144`; Green hosting `178.18.126.128`; Web builder may use different IPs |
| **CNAME** | `www` | `clawhatch.co.uk` **or** host target shown in panel | Remove `fwd3.hosts.co.uk` parking CNAME |
| **MX** | `@` | Only if using names.co.uk email (`athena` / `hermes` etc.) | From panel if you enable email |

**Current public records (before you change them):**
- Apex **A** → `85.233.160.22` (forwarding/parking style)
- **www** CNAME → `fwd3.hosts.co.uk` (parked)

Replace those with the **hosting** records from your package (not the parked forward).

Official help:
- https://www.names.co.uk/support/articles/changing-your-domains-dns-settings/
- https://www.names.co.uk/support/articles/what-is-dns-and-what-are-nameservers/

---

## B. GitHub → website URL (clawhatch.co.uk)

On [clawhatch/clawhatch](https://github.com/clawhatch/clawhatch):

1. **Settings → General → Website**
   Set to: `https://clawhatch.co.uk`
2. **About** (gear on repo home) → Website: same URL
3. In **package.json** (when you can push):
   ```json
   "homepage": "https://clawhatch.co.uk",
   "repository": {
     "type": "git",
     "url": "git+https://github.com/clawhatch/clawhatch.git"
   },
   "bugs": { "url": "https://github.com/clawhatch/clawhatch/issues" }
   ```
4. README: add a line
   `Website: https://clawhatch.co.uk`
   and keep `npx clawhatch scan` as the product CTA.
5. npm (optional later):
   `npm pkg set homepage=https://clawhatch.co.uk` then publish a patch when ready.

---

## C. What not to do

- Do **not** leave www on `fwd3.hosts.co.uk` if you want a real site.
- Do **not** point GitHub Website at `names.co.uk` corporate homepage — use **your** domain `https://clawhatch.co.uk`.
- Do **not** mix Vercel A `76.76.21.21` with names.co.uk shared hosting unless you intentionally host on Vercel instead.

---

## D. Verify when done

```bash
# Apex should be your hosting IP (not only parking)
dig +short A clawhatch.co.uk

# www should not be fwd3.hosts.co.uk
dig +short CNAME www.clawhatch.co.uk

curl -sI https://clawhatch.co.uk | head -10
```

Browser: open `https://clawhatch.co.uk` — you should see **your** page, not the parked-domains iframe.
