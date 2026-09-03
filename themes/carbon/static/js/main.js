(function () {
  var root = document.documentElement;
  var btn = document.getElementById("theme-toggle");
  var stored = null;
  try { stored = localStorage.getItem("theme"); } catch (e) {}
  if (stored) root.setAttribute("data-theme", stored);

  function current() {
    var attr = root.getAttribute("data-theme");
    if (attr) return attr;
    return window.matchMedia("(prefers-color-scheme: dark)").matches ? "dark" : "light";
  }

  if (btn) {
    btn.addEventListener("click", function () {
      var next = current() === "dark" ? "light" : "dark";
      root.setAttribute("data-theme", next);
      try { localStorage.setItem("theme", next); } catch (e) {}
    });
  }
})();
