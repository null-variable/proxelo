// Sets the color mode before the first paint: the saved choice, else the
// system preference. A separate file keeps the CSP free of inline scripts.
(function () {
  var m = localStorage.getItem("proxelo.mode");
  if (m !== "light" && m !== "dark") {
    m = window.matchMedia && window.matchMedia("(prefers-color-scheme: dark)").matches ? "dark" : "light";
  }
  document.documentElement.dataset.mode = m;
})();
