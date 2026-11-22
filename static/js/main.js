/* Stages 9-10 — Progressive enhancement for the phishing detection UI.
 *
 * All behaviour is attached from this EXTERNAL file. There is no inline
 * script, no inline style attribute, no dynamic code execution and no DOM
 * markup injection: `services/http_security.py` sends `script-src 'self'`
 * and `style-src 'self'` with no 'unsafe-inline', and this file respects that.
 *
 * Data reaches JavaScript through escaped `data-*` attributes rendered by
 * Jinja (`|tojson`), never through an inline <script> block. The only chart
 * in Stage 9 shows REAL dataset split row counts read at runtime from
 * ml/saved_model/metadata.json — no invented statistic is plotted.
 */
(function () {
  "use strict";

  var THEME_KEY = "pds-theme";
  var charts = [];

  function readStoredTheme() {
    try {
      return window.localStorage.getItem(THEME_KEY);
    } catch (ignored) {
      return null;
    }
  }

  function storeTheme(theme) {
    try {
      window.localStorage.setItem(THEME_KEY, theme);
    } catch (ignored) {
      /* Sandboxed preview: persistence is unavailable, in-page toggle still works. */
    }
  }

  function cssVar(name) {
    return window.getComputedStyle(document.documentElement)
      .getPropertyValue(name).trim();
  }

  function currentTheme() {
    var attr = document.documentElement.getAttribute("data-theme");
    return attr === "light" ? "light" : "dark";
  }

  function updateThemeButton() {
    var button = document.getElementById("themeToggle");
    if (!button) {
      return;
    }
    var theme = currentTheme();
    var isLight = theme === "light";
    button.setAttribute("aria-pressed", String(isLight));
    button.setAttribute("aria-label", isLight ? "Switch to dark theme" : "Switch to light theme");
    button.setAttribute("title", isLight ? "Switch to dark theme" : "Switch to light theme");
    var icon = button.querySelector("[data-theme-icon]");
    if (icon) {
      icon.textContent = isLight ? "\u263E" : "\u2600";
    }
  }

  function applyTheme(theme, persist) {
    document.documentElement.setAttribute("data-theme", theme);
    if (persist) {
      storeTheme(theme);
    }
    updateThemeButton();
    refreshChartColours();
  }

  function initThemeToggle() {
    var button = document.getElementById("themeToggle");
    updateThemeButton();
    if (!button) {
      return;
    }
    button.addEventListener("click", function () {
      applyTheme(currentTheme() === "light" ? "dark" : "light", true);
    });
  }

  /* ---- Chart.js: data comes only from an escaped data-* attribute --------- */
  function chartPalette() {
    return {
      text: cssVar("--pds-text") || "#e6eef7",
      muted: cssVar("--pds-muted") || "#a8bdd2",
      line: cssVar("--pds-line") || "#22344a",
      panel: cssVar("--pds-panel") || "#101a26",
      accent: cssVar("--pds-accent") || "#22d3ee",
      ok: cssVar("--pds-ok") || "#34d399",
      warn: cssVar("--pds-warn") || "#fbbf24"
    };
  }

  /* Stage 11: repeat the three theme colours so a chart can hold any number
     of categories (e.g. seven daily bars) without a hard-coded palette. */
  function cycledColours(palette, length) {
    var base = [palette.accent, palette.ok, palette.warn];
    var result = [];
    for (var i = 0; i < length; i += 1) {
      result.push(base[i % base.length]);
    }
    return result;
  }

  function buildChartConfig(payload, palette, chartType) {
    var type = chartType === "bar" ? "bar" : "doughnut";
    var base = {
      type: type,
      data: {
        labels: payload.labels,
        datasets: [{
          label: payload.series_label || "Rows",
          data: payload.values,
          backgroundColor: cycledColours(palette, payload.values.length),
          borderColor: palette.panel,
          borderWidth: type === "doughnut" ? 3 : 1,
          hoverOffset: type === "doughnut" ? 10 : 0
        }]
      },
      options: {
        responsive: true,
        maintainAspectRatio: false,
        animation: { duration: 350 },
        plugins: {
          legend: {
            position: "bottom",
            labels: { color: palette.text, padding: 14, boxWidth: 14, font: { size: 12 } }
          },
          tooltip: {
            backgroundColor: palette.panel,
            titleColor: palette.text,
            bodyColor: palette.text,
            borderColor: palette.line,
            borderWidth: 1,
            callbacks: {}
          }
        }
      }
    };
    if (type === "bar") {
      base.options.scales = {
        x: { ticks: { color: palette.muted }, grid: { color: palette.line } },
        y: { beginAtZero: true, ticks: { color: palette.muted }, grid: { color: palette.line } }
      };
      base.options.plugins.legend.display = false;
    }
    return base;
  }

  function refreshChartColours() {
    var palette = chartPalette();
    charts.forEach(function (chart) {
      chart.options.plugins.legend.labels.color = palette.text;
      chart.options.plugins.tooltip.backgroundColor = palette.panel;
      chart.options.plugins.tooltip.titleColor = palette.text;
      chart.options.plugins.tooltip.bodyColor = palette.text;
      chart.options.plugins.tooltip.borderColor = palette.line;
      chart.data.datasets[0].borderColor = palette.panel;
      chart.data.datasets[0].backgroundColor = cycledColours(
        palette, chart.data.datasets[0].data.length
      );
      if (chart.options.scales) {
        chart.options.scales.x.ticks.color = palette.muted;
        chart.options.scales.y.ticks.color = palette.muted;
        chart.options.scales.x.grid.color = palette.line;
        chart.options.scales.y.grid.color = palette.line;
      }
      chart.update("none");
    });
  }

  function initCharts() {
    var nodes = document.querySelectorAll("[data-chart]");
    if (!nodes.length) {
      return;
    }
    if (typeof window.Chart === "undefined") {
      Array.prototype.forEach.call(nodes, function (node) {
        var note = node.querySelector("[data-chart-fallback]");
        if (note) {
          note.textContent = "Chart library is unavailable; the source data is listed below.";
        }
      });
      return;
    }
    Array.prototype.forEach.call(nodes, function (node) {
      var raw = node.getAttribute("data-chart") || "";
      var payload;
      try {
        payload = JSON.parse(raw);
      } catch (ignored) {
        return;
      }
      if (!payload || !Array.isArray(payload.labels) || !Array.isArray(payload.values)) {
        return;
      }
      var canvas = node.querySelector("canvas");
      if (!canvas) {
        return;
      }
      var config = buildChartConfig(payload, chartPalette(), node.getAttribute("data-chart-type"));
      charts.push(new window.Chart(canvas, config));
    });
  }

  /* ---- navigation & small utilities --------------------------------------- */
  function initActiveNav() {
    var path = window.location.pathname;
    var links = document.querySelectorAll(".pds-nav-link[data-nav-path]");
    Array.prototype.forEach.call(links, function (link) {
      var target = link.getAttribute("data-nav-path");
      if (target && (path === target || (target !== "/" && path.indexOf(target) === 0))) {
        link.classList.add("is-active");
        link.setAttribute("aria-current", "page");
      }
    });
  }

  function announce(button, text) {
    var live = document.getElementById("pdsLiveRegion");
    if (live) {
      live.textContent = text;
    }
    if (button) {
      var original = button.getAttribute("data-original-label") || button.textContent;
      button.setAttribute("data-original-label", original);
      button.textContent = text;
      window.setTimeout(function () {
        button.textContent = original;
      }, 2200);
    }
  }

  function initCopyButtons() {
    var buttons = document.querySelectorAll("[data-copy-target]");
    Array.prototype.forEach.call(buttons, function (button) {
      button.addEventListener("click", function () {
        var selector = button.getAttribute("data-copy-target");
        var source = selector ? document.querySelector(selector) : null;
        if (!source || !navigator.clipboard || !navigator.clipboard.writeText) {
          announce(button, "Copy unavailable");
          return;
        }
        navigator.clipboard.writeText(source.textContent.trim()).then(function () {
          announce(button, "Copied");
        }).catch(function () {
          announce(button, "Copy unavailable");
        });
      });
    });
  }

  /* Stage 10: printing is a progressive enhancement, so no inline handler
     is needed and the strict CSP stays unchanged. */
  function initPrintButtons() {
    var buttons = document.querySelectorAll("[data-print]");
    Array.prototype.forEach.call(buttons, function (button) {
      button.addEventListener("click", function () {
        if (window.print) {
          window.print();
        } else {
          announce(button, "Print unavailable");
        }
      });
    });
  }

  function init() {
    var stored = readStoredTheme();
    if (stored === "light" || stored === "dark") {
      applyTheme(stored, false);
    } else {
      updateThemeButton();
    }
    initThemeToggle();
    initActiveNav();
    initCopyButtons();
    initPrintButtons();
    initCharts();
  }

  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", init);
  } else {
    init();
  }
})();
