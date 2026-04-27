/* Protocol Guardian — theme manager
 * Synchronous, head-loaded, FOUC-safe.
 * - Reads localStorage('protoguardian-theme'); falls back to prefers-color-scheme.
 * - Sets data-theme="light" | "dark" on <html>.
 * - Listens to system preference changes when the user hasn't picked.
 * - Wires any [data-theme-toggle] buttons (sets aria-pressed, aria-label, click toggles).
 * - Updates <meta name="theme-color">.
 * - Exposes window.ProtoGuardianTheme.{get,set,clear}.
 */
(function () {
  var STORAGE_KEY = 'protoguardian-theme';
  var DOC = document.documentElement;
  var META_LIGHT = '#fbfcff';
  var META_DARK = '#0b0e1a';

  function safeGetStored() {
    try {
      var v = window.localStorage.getItem(STORAGE_KEY);
      return v === 'light' || v === 'dark' ? v : null;
    } catch (e) {
      return null;
    }
  }

  function safeSetStored(v) {
    try { window.localStorage.setItem(STORAGE_KEY, v); } catch (e) { /* no-op */ }
  }

  function safeClearStored() {
    try { window.localStorage.removeItem(STORAGE_KEY); } catch (e) { /* no-op */ }
  }

  function systemPref() {
    return window.matchMedia && window.matchMedia('(prefers-color-scheme: dark)').matches ? 'dark' : 'light';
  }

  function effective() {
    return safeGetStored() || systemPref();
  }

  function updateMetaThemeColor(theme) {
    var meta = document.querySelector('meta[name="theme-color"]');
    if (!meta) {
      meta = document.createElement('meta');
      meta.setAttribute('name', 'theme-color');
      document.head.appendChild(meta);
    }
    meta.setAttribute('content', theme === 'dark' ? META_DARK : META_LIGHT);
  }

  function syncToggleButtons(theme) {
    var btns = document.querySelectorAll('[data-theme-toggle]');
    for (var i = 0; i < btns.length; i++) {
      var b = btns[i];
      b.setAttribute('aria-pressed', theme === 'dark' ? 'true' : 'false');
      b.setAttribute('aria-label', theme === 'dark' ? 'Switch to light mode' : 'Switch to dark mode');
      b.setAttribute('title', theme === 'dark' ? 'Switch to light mode' : 'Switch to dark mode');
    }
  }

  function apply(theme) {
    DOC.setAttribute('data-theme', theme);
    updateMetaThemeColor(theme);
    syncToggleButtons(theme);
  }

  // Apply ASAP, before paint, to prevent FOUC.
  apply(effective());

  function set(theme) {
    if (theme !== 'light' && theme !== 'dark') return;
    safeSetStored(theme);
    apply(theme);
  }

  function get() {
    return DOC.getAttribute('data-theme') || effective();
  }

  function clear() {
    safeClearStored();
    apply(systemPref());
  }

  // Listen to system preference changes only when user hasn't explicitly picked.
  if (window.matchMedia) {
    var mql = window.matchMedia('(prefers-color-scheme: dark)');
    var handler = function (e) {
      if (!safeGetStored()) {
        apply(e.matches ? 'dark' : 'light');
      }
    };
    if (mql.addEventListener) mql.addEventListener('change', handler);
    else if (mql.addListener) mql.addListener(handler);
  }

  // Wire up [data-theme-toggle] buttons after DOM ready.
  function wireToggles() {
    var btns = document.querySelectorAll('[data-theme-toggle]');
    for (var i = 0; i < btns.length; i++) {
      (function (btn) {
        if (btn.__pgWired) return;
        btn.__pgWired = true;
        btn.addEventListener('click', function () {
          set(get() === 'dark' ? 'light' : 'dark');
        });
      })(btns[i]);
    }
    syncToggleButtons(get());
  }

  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', wireToggles);
  } else {
    wireToggles();
  }

  window.ProtoGuardianTheme = { get: get, set: set, clear: clear };
})();
