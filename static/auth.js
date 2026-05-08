(function () {
  var body = document.body;
  var initTab = body.dataset.initTab || "login";
  var initError = body.dataset.initError || "";

  function activate(tabName) {
    document.querySelectorAll(".auth-tab").forEach(function (btn) {
      btn.classList.toggle("active", btn.dataset.for === tabName);
    });
    document.querySelectorAll("[data-panel]").forEach(function (panel) {
      panel.classList.toggle("active", panel.dataset.panel === tabName);
    });
  }

  document.querySelectorAll(".auth-tab").forEach(function (btn) {
    btn.addEventListener("click", function () { activate(btn.dataset.for); });
  });

  activate(initTab);

  if (initError && initError !== "None" && initError.trim() !== "" && !initError.includes("{" + "{")) {
    var el = document.getElementById("authError");
    if (el) {
      el.textContent = initError;
      el.classList.add("visible");
    }
  }
})();
