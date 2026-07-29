# Publish clawhatch.co.uk from GitHub Pages

The production source is `clawhatch/clawhatch/website` on `main`.
The verified static output is published from the repository's `gh-pages`
branch.

Until the registrar records are changed, the site is available at:

`https://clawhatch.github.io/clawhatch/`

## names.co.uk DNS

Log in to `https://admin.names.co.uk`, open `clawhatch.co.uk`, then open DNS
management.

Remove the parked-domain records:

- Apex `A` → `85.233.160.22`
- `www` `CNAME` → `fwd3.hosts.co.uk`

Add the GitHub Pages records:

| Type | Host | Value |
|---|---|---|
| A | `@` | `185.199.108.153` |
| A | `@` | `185.199.109.153` |
| A | `@` | `185.199.110.153` |
| A | `@` | `185.199.111.153` |
| CNAME | `www` | `clawhatch.github.io` |

Keep the existing nameservers and MX records so domain ownership and email are
not disrupted.

## GitHub Pages

After DNS resolves to GitHub Pages:

1. Repository Settings → Pages.
2. Set the custom domain to `clawhatch.co.uk`.
3. Wait for the TLS certificate to be issued.
4. Enable **Enforce HTTPS**.
5. Verify that `www.clawhatch.co.uk` redirects to the apex domain.

GitHub's current DNS instructions:

`https://docs.github.com/en/pages/configuring-a-custom-domain-for-your-github-pages-site/managing-a-custom-domain-for-your-github-pages-site`

## Verify

```bash
dig +short A clawhatch.co.uk
dig +short CNAME www.clawhatch.co.uk
curl -sI https://clawhatch.co.uk
curl -sI https://clawhatch.co.uk/world
```

Expected apex values are the four `185.199.*.153` addresses above. `www`
should resolve through `clawhatch.github.io`, and both web requests should
return a successful HTTPS response.
