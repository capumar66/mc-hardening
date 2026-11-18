try {
  var saved = localStorage.getItem("color-scheme");
  var meta = document.querySelector('meta[name="color-scheme"]');
  if (meta) {
    meta.content = saved === "light" || saved === "dark" ? saved : "light dark";
  }
} catch (_) {
  // Ignore storage access errors in restricted browser contexts
}
