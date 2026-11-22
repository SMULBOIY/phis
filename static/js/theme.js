/* Stage 9 — early theme bootstrap.
 *
 * Loaded as a normal, blocking EXTERNAL script in <head> so the correct
 * palette is applied before the browser paints the page. That avoids the
 * "flash of wrong theme" without needing an inline <script>, which the strict
 * Content-Security-Policy (`script-src 'self'`) forbids.
 *
 * The Arena preview iframe is sandboxed with allow-scripts but without
 * allow-same-origin, so localStorage access can throw SecurityError. Every
 * storage access is guarded; the UI simply falls back to the OS preference
 * and then to the dark default.
 */
(function () {
  "use strict";
  var chosen = null;
  try {
    var saved = window.localStorage.getItem("pds-theme");
    if (saved === "light" || saved === "dark") {
      chosen = saved;
    }
  } catch (ignored) {
    chosen = null;
  }
  if (!chosen && window.matchMedia && window.matchMedia("(prefers-color-scheme: light)").matches) {
    chosen = "light";
  }
  document.documentElement.setAttribute("data-theme", chosen || "dark");
})();
