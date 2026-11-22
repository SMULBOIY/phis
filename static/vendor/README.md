# Vendored frontend libraries (Stage 9)

These three files are copied **unmodified** from the jsDelivr CDN so the UI
works completely offline and the Content-Security-Policy can stay at
`default-src 'self'` — no CDN, no external fonts, no network at render time.
This also matters for the in-app file viewer, whose sandboxed iframe has no
network access.

| File | Upstream | Version | Size | SHA-256 |
| --- | --- | --- | --- | --- |
| `bootstrap.min.css` | `https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/css/bootstrap.min.css` | 5.3.3 (MIT) | 232,803 bytes | `3c8f27e6009ccfd710a905e6dcf12d0ee3c6f2ac7da05b0572d3e0d12e736fc8` |
| `bootstrap.bundle.min.js` | `https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/js/bootstrap.bundle.min.js` | 5.3.3 (MIT, includes Popper) | 80,721 bytes | `0833b2e9c3a26c258476c46266e6877fc75218625162e0460be9a3a098a61c6c` |
| `chart.umd.min.js` | `https://cdn.jsdelivr.net/npm/chart.js@4.4.4/dist/chart.umd.min.js` | 4.4.4 (MIT) | 205,749 bytes | `b38076762f7363bc9e912b68b8e034826798db5df26bb61f000ec2e7a3137bc7` |

`chart.umd.min.js` is the upstream UMD distribution; Chart.js 4.4.4 ships this
file already bundled and jsDelivr notes that no further minification was
applied. It defines the global `Chart`. It is loaded locally with `defer` on
pages that render a chart.

The files are kept **byte-for-byte identical** to the upstream downloads so the
hashes above are independently verifiable. Each contains a trailing
`sourceMappingURL` comment pointing at a `.map` file that is deliberately not
vendored (it is only useful for debugging the library itself, and would add
megabytes to the repository). Browsers request those maps only when developer
tools are open; the resulting same-origin 404 is harmless and does not affect
the UI or the Content-Security-Policy.

## Verify after copying to your own machine (Windows / PowerShell)

```powershell
Get-FileHash static\vendor\bootstrap.min.css -Algorithm SHA256
Get-FileHash static\vendor\bootstrap.bundle.min.js -Algorithm SHA256
Get-FileHash static\vendor\chart.umd.min.js -Algorithm SHA256
```

Compare with the table above. `scripts/verify_stage9.py` recomputes all three
hashes automatically, so a partial download or a swapped file fails the gate.

## Why not a CDN `<link>` / `<script>` tag?

1. **CSP.** `services/http_security.py` sends `script-src 'self'` and
   `style-src 'self'` with no `unsafe-inline`. A CDN origin would need an
   allow-list entry, widening the attack surface.
2. **Offline / exam demo.** A viva or lab machine may have no internet. A local
   copy renders identically.
3. **Reproducibility.** Pinned versions plus recorded hashes mean the exact UI
   can be reconstructed from this repository.

## Licensing

Bootstrap and Chart.js are both MIT-licensed. Their upstream licence headers
are preserved verbatim at the top of each file. Attribution is recorded here
and in `docs/UI.md` §4.
