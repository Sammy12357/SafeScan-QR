// Live leaderboard. External (not inline) because the site CSP is
// script-src 'self' with no inline scripts allowed — an inline version is
// silently blocked by the browser and never runs.
(function () {
  // Live leaderboard: poll the JSON API and rebuild the table in place
  // so the board stays current without a full page reload.
  var body = document.getElementById("lbBody");
  var shell = document.querySelector(".lb-shell");
  if (!shell) return;
  function medal(rank) {
    if (rank === 1) return "\u{1F947}";
    if (rank === 2) return "\u{1F948}";
    if (rank === 3) return "\u{1F949}";
    return String(rank);
  }
  function esc(s) {
    var d = document.createElement("div");
    d.textContent = s == null ? "" : String(s);
    return d.innerHTML;
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
      if (empty) empty.style.display = "";
      return;
    }
    if (empty) empty.style.display = "none";
    if (table) table.style.display = "";
    var tbody = document.getElementById("lbBody");
    if (!tbody) return;
    tbody.innerHTML = entries.map(function (row) {
      var rank = row.rank || 0;
      var top = rank <= 3 ? " lb-rank-top" : "";
      var youRow = row.isCurrentUser ? " current-user" : "";
      var youName = row.isCurrentUser ? " lb-username-you" : "";
      return "<tr class=\"" + youRow.trim() + "\">" +
        "<td class=\"lb-rank" + top + "\">" + medal(rank) + "</td>" +
        "<td class=\"lb-username" + youName + "\">" + esc(row.name) + "</td>" +
        "<td class=\"lb-num\">" + (row.scans || 0) + "</td>" +
        "<td class=\"lb-num\">" + (row.totalSaved || 0) + "</td>" +
        "<td class=\"lb-date\">" + esc(formatLocal(row.lastScannedAt)) + "</td>" +
        "</tr>";
    }).join("");
  }
  function refresh() {
    fetch("/api/leaderboard?limit=50", { credentials: "same-origin", headers: { "Accept": "application/json" } })
      .then(function (r) { return r.ok ? r.json() : null; })
      .then(function (data) { if (data && data.entries) render(data.entries); })
      .catch(function () { /* keep the last good board on transient errors */ });
  }
  localizeStaticDates();
  refresh();
  var timer = setInterval(refresh, 20000);
  document.addEventListener("visibilitychange", function () {
    if (document.visibilityState === "visible") refresh();
  });
})();
