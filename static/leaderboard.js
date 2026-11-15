// Live leaderboard. External (not inline) because the site CSP is
// script-src 'self' with no inline scripts allowed — an inline version is
// silently blocked by the browser and never runs.
(function () {
  // Live leaderboard: poll the JSON API and rebuild the table in place
  // so the board stays current without a full page reload.
  var body = document.getElementById("lbBody");
  var shell = document.querySelector(".lb-shell");
  if (!shell) return;
  var refreshState = document.createElement("div");
  refreshState.id = "lbRefreshState";
  refreshState.hidden = true;
  shell.querySelector(".lb-sub")?.after(refreshState);
  var refreshInFlight = false;
  function medal(rank) {
    if (rank === 1) return "\u{1F947}";
    if (rank === 2) return "\u{1F948}";
    if (rank === 3) return "\u{1F949}";
    return String(rank);
  }
  function formatLocal(iso) {
    if (!iso) return "—";
    // Timestamps are stored in UTC. Treat any value without an explicit
    // timezone designator as UTC so every visitor sees the same instant
    // rendered in their own local time zone.
    var s = String(iso);
    if (!/[zZ]$|[+-]\d{2}:?\d{2}$/.test(s)) s += "Z";
    var d = new Date(s);
    if (isNaN(d.getTime())) return "—";
    try {
      return d.toLocaleString([], { dateStyle: "medium", timeStyle: "short" });
    } catch (e) {
      return d.toLocaleString();
    }
  }
  function localizeStaticDates() {
    // Convert the server-rendered rows to local time immediately so there is
    // no flash of server-time before the first API refresh arrives.
    var cells = document.querySelectorAll("#lbBody [data-utc]");
    for (var i = 0; i < cells.length; i++) {
      var v = cells[i].getAttribute("data-utc");
      cells[i].textContent = v ? formatLocal(v) : "—";
    }
  }
  function render(entries) {
    var table = document.getElementById("lbTable");
    var empty = document.querySelector(".lb-empty");
    if (!entries || !entries.length) {
      if (table) table.style.display = "none";
      if (empty) empty.classList.remove("lb-initially-hidden");
      if (empty) empty.style.display = "";
      return;
    }
    if (empty) empty.style.display = "none";
    if (table) table.classList.remove("lb-initially-hidden");
    if (table) table.style.display = "";
    var tbody = document.getElementById("lbBody");
    if (!tbody) return;
    var rows = entries.map(function (row) {
      var rank = Number(row.rank);
      var tr = document.createElement("tr");
      if (row.isCurrentUser) tr.classList.add("current-user");
      function cell(className, value) {
        var td = document.createElement("td");
        td.className = className;
        td.textContent = String(value);
        tr.appendChild(td);
      }
      cell("lb-rank" + (Number.isFinite(rank) && rank >= 1 && rank <= 3 ? " lb-rank-top" : ""), Number.isFinite(rank) ? medal(rank) : "—");
      cell("lb-username" + (row.isCurrentUser ? " lb-username-you" : ""), row.name || "Anonymous");
      cell("lb-num", Number.isFinite(Number(row.scans)) ? Number(row.scans) : 0);
      cell("lb-num", Number.isFinite(Number(row.totalSaved)) ? Number(row.totalSaved) : 0);
      cell("lb-date", formatLocal(row.lastScannedAt));
      return tr;
    });
    tbody.replaceChildren(...rows);
  }
  function refresh() {
    if (refreshInFlight) return;
    refreshInFlight = true;
    var hadRows = Boolean(body && body.querySelector("tr"));
    refreshState.hidden = false;
    if (body) body.setAttribute("aria-busy", "true");
    var controller = new AbortController();
    var timedOut = false;
    var operation = UIStates.loading(refreshState, {
      label: "Refreshing leaderboard",
      compact: true,
      delayMs: 1000,
      timeoutTitle: hadRows ? "Leaderboard didn't refresh" : "Leaderboard didn't load",
      timeoutBody: hadRows ? "These are previous results. Try again to update them." : "Check your connection and try again.",
      retry: refresh,
      onTimeout: function () {
        timedOut = true;
        controller.abort();
        refreshInFlight = false;
        if (body) body.removeAttribute("aria-busy");
        if (!hadRows) {
          var empty = document.querySelector(".lb-empty");
          if (empty) empty.style.display = "none";
        }
      }
    });
    UIStates.fetchJson("/api/leaderboard?limit=50", { credentials: "same-origin", signal: controller.signal })
      .then(function (data) {
        if (timedOut) return;
        if (!data || !Array.isArray(data.entries)) throw new Error("Unexpected leaderboard response");
        operation.finish();
        refreshState.replaceChildren();
        refreshState.hidden = true;
        render(data.entries);
        refreshInFlight = false;
        if (body) body.removeAttribute("aria-busy");
      })
      .catch(function (problem) {
        if (timedOut) return;
        operation.finish();
        refreshInFlight = false;
        if (body) body.removeAttribute("aria-busy");
        var hasRows = Boolean(body && body.querySelector("tr"));
        if (!hasRows) {
          var empty = document.querySelector(".lb-empty");
          if (empty) empty.style.display = "none";
        }
        refreshState.hidden = false;
        UIStates.notice(refreshState, {
          type: "warning",
          message: hasRows
            ? problem && problem.code === "offline"
              ? "You're offline. Showing the last results."
              : "The leaderboard didn't refresh. Showing the last results."
            : problem && problem.code === "offline"
              ? "You're offline. Reconnect to load the leaderboard."
              : "The leaderboard didn't load. Check your connection and try again."
        });
        var retry = document.createElement("button");
        retry.type = "button";
        retry.className = "secondary-button";
        retry.textContent = "Try again";
        retry.addEventListener("click", refresh);
        var actions = document.createElement("div");
        actions.className = "state-actions";
        actions.appendChild(retry);
        refreshState.appendChild(actions);
      });
  }
  localizeStaticDates();
  refresh();
  var timer = setInterval(refresh, 20000);
  document.addEventListener("visibilitychange", function () {
    if (document.visibilityState === "visible") refresh();
  });
  window.addEventListener("online", refresh);
})();
