// Applies a saved light/dark choice before first paint. Without one, CSS follows the OS setting.
(function () {
  var saved = null;
  try { saved = localStorage.getItem('st-theme'); } catch (e) { /* storage unavailable */ }
  if (saved === 'light' || saved === 'dark') document.documentElement.setAttribute('data-theme', saved);
})();
