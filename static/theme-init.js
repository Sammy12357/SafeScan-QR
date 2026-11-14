// Apply the saved appearance before CSS paints, so navigation between pages
// does not briefly show the default theme.
(function () {
  var theme = "dark";
  try {
    if (localStorage.getItem("safescan_theme") === "light") theme = "light";
  } catch (e) {}
  document.documentElement.setAttribute("data-theme", theme);
})();
