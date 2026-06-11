// Collapsible left side navigation drawer. External (not inline) because the
// site CSP is script-src 'self'. Toggles `sidenav-open` on <body>; CSS handles
// the slide + backdrop. Remembers the open/closed choice for the session.
(function () {
  var toggle = document.querySelector(".sidenav-toggle");
  var nav = document.getElementById("sideNav");
  if (!toggle || !nav) return;

  function setOpen(open) {
    document.body.classList.toggle("sidenav-open", open);
    toggle.setAttribute("aria-expanded", open ? "true" : "false");
    nav.setAttribute("aria-hidden", open ? "false" : "true");
    try { sessionStorage.setItem("safescan_sidenav_open", open ? "1" : "0"); } catch (e) {}
  }

  toggle.addEventListener("click", function () {
    setOpen(!document.body.classList.contains("sidenav-open"));
  });

  // Close on backdrop / close-button click.
  var closers = document.querySelectorAll("[data-sidenav-close]");
  for (var i = 0; i < closers.length; i++) {
    closers[i].addEventListener("click", function () { setOpen(false); });
  }

  // Close on Escape.
  document.addEventListener("keydown", function (e) {
    if (e.key === "Escape" && document.body.classList.contains("sidenav-open")) setOpen(false);
  });

  // Close after following a link inside the drawer (so navigation feels clean).
  var links = nav.querySelectorAll(".sidenav-link[href]");
  for (var j = 0; j < links.length; j++) {
    links[j].addEventListener("click", function () { setOpen(false); });
  }

  // Restore the previous state on load (defaults to closed).
  var saved = null;
  try { saved = sessionStorage.getItem("safescan_sidenav_open"); } catch (e) {}
  if (saved === "1") setOpen(true);

  // Theme switching. There can be more than one toggle on the page (top bar
  // on desktop, inside the drawer on mobile) - bind and sync all of them.
  var themeToggles = document.querySelectorAll("[data-theme-toggle]");
  var themeToggleTexts = document.querySelectorAll("[data-theme-toggle-text]");
  var themeKey = "safescan_theme";

  function preferredTheme() {
    try {
      var savedTheme = localStorage.getItem(themeKey);
      if (savedTheme === "light" || savedTheme === "dark") return savedTheme;
    } catch (e) {}
    return "dark";
  }

  function setTheme(theme) {
    var nextTheme = theme === "light" ? "light" : "dark";
    var isLight = nextTheme === "light";
    document.documentElement.setAttribute("data-theme", nextTheme);
    for (var t = 0; t < themeToggles.length; t++) {
      themeToggles[t].setAttribute("aria-pressed", isLight ? "true" : "false");
      themeToggles[t].setAttribute("aria-label", isLight ? "Switch to dark mode" : "Switch to light mode");
    }
    for (var x = 0; x < themeToggleTexts.length; x++) {
      themeToggleTexts[x].textContent = isLight ? "Light" : "Dark";
    }
    try { localStorage.setItem(themeKey, nextTheme); } catch (e) {}
  }

  setTheme(preferredTheme());
  for (var k = 0; k < themeToggles.length; k++) {
    themeToggles[k].addEventListener("click", function () {
      setTheme(document.documentElement.getAttribute("data-theme") === "light" ? "dark" : "light");
    });
  }
})();
