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

  var googleConfig = document.getElementById("g_id_onload");
  var googleMount = document.getElementById("googleButtonMount");
  var googleFallbackButton = document.getElementById("googleFallbackButton");
  var googleStatus = document.getElementById("googleSignInStatus");

  function setGoogleStatus(message) {
    if (googleStatus) googleStatus.textContent = message;
  }

  function renderGoogleButton() {
    if (!googleConfig || !googleMount || !window.google || !window.google.accounts || !window.google.accounts.id) {
      return false;
    }

    var clientId = googleConfig.dataset.client_id || googleConfig.dataset.clientId || "";
    var loginUri = googleConfig.dataset.login_uri || googleConfig.dataset.loginUri || "";
    var state = googleConfig.dataset.state || "";
    if (!clientId || !loginUri) return false;

    try {
      window.google.accounts.id.initialize({
        client_id: clientId,
        login_uri: loginUri,
        state: state,
        ux_mode: "redirect"
      });
      window.google.accounts.id.renderButton(googleMount, {
        type: "standard",
        theme: "filled_black",
        size: "large",
        text: "continue_with",
        shape: "rectangular",
        logo_alignment: "left",
        width: Math.min(356, Math.max(240, googleMount.clientWidth || 356))
      });
      setGoogleStatus("Use the Google button above. If Phantom does not show it, tap Continue with Google.");
      return true;
    } catch (error) {
      setGoogleStatus("Google sign-in could not render in this browser. Tap Continue with Google to try the redirect prompt.");
      return false;
    }
  }

  function tryGooglePrompt() {
    if (!renderGoogleButton()) {
      setGoogleStatus("Google sign-in is still loading. Wait a moment, then tap again.");
      return;
    }

    try {
      window.google.accounts.id.prompt(function (notification) {
        if (!notification) return;
        if (notification.isNotDisplayed && notification.isNotDisplayed()) {
          setGoogleStatus("Phantom blocked Google's prompt. Use the Google button above, or sign in with email first.");
        } else if (notification.isSkippedMoment && notification.isSkippedMoment()) {
          setGoogleStatus("Google skipped the prompt in this browser. Use the Google button above, or sign in with email first.");
        }
      });
    } catch (error) {
      setGoogleStatus("Google sign-in could not start in this browser. Use the Google button above, or sign in with email first.");
    }
  }

  if (googleConfig) {
    var attempts = 0;
    var timer = window.setInterval(function () {
      attempts += 1;
      if (renderGoogleButton() || attempts >= 20) {
        window.clearInterval(timer);
        if (attempts >= 20 && !googleMount.querySelector("iframe")) {
          setGoogleStatus("Google sign-in did not render automatically in Phantom. Tap Continue with Google to retry.");
        }
      }
    }, 250);
  }

  if (googleFallbackButton) {
    googleFallbackButton.addEventListener("click", tryGooglePrompt);
  }

  activate(initTab);

  if (initError && initError !== "None" && initError.trim() !== "" && !initError.includes("{" + "{")) {
    var el = document.getElementById("authError");
    if (el) {
      el.textContent = initError;
      el.classList.add("visible");
    }
  }
})();
