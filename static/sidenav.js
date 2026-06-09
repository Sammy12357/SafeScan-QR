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
})();
