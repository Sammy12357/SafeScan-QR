// Malicious QR Database page: fetches the public threat feed and renders it
// with client-side search and pagination. Lives in /static (external script)
// because the site CSP is script-src 'self' with no inline scripts allowed.
(function () {
  var grid = document.getElementById("mqGrid");
  var stateEl = document.getElementById("mqState");
  var countEl = document.getElementById("mqCount");
  var pageInfo = document.getElementById("mqPageInfo");
  var prevBtn = document.getElementById("mqPrev");
  var nextBtn = document.getElementById("mqNext");
  var searchEl = document.getElementById("mqSearch");
  var statsEl = document.getElementById("mqStats");
  var statTotal = document.getElementById("mqStatTotal");
  var statReports = document.getElementById("mqStatReports");
  var statUpdated = document.getElementById("mqStatUpdated");
  if (!grid) return;

  var LIMIT = parseInt(grid.getAttribute("data-limit"), 10) || 20;
  var state = { page: 1, totalPages: 1, total: 0, query: "", loading: false };

  function esc(s) {
    var d = document.createElement("div");
    d.textContent = s == null ? "" : String(s);
    return d.innerHTML;
  }
  function formatLocal(iso) {
    if (!iso) return "Unknown";
    // Timestamps are stored in UTC; treat tz-less values as UTC so each
    // visitor sees the time in their own local zone.
    var s = String(iso);
    if (!/[zZ]$|[+-]\d{2}:?\d{2}$/.test(s)) s += "Z";
    var d = new Date(s);
    if (isNaN(d.getTime())) return "Unknown";
    try { return d.toLocaleString([], { dateStyle: "medium", timeStyle: "short" }); }
    catch (e) { return d.toLocaleString(); }
  }
  function cardHtml(row) {
    return '<div class="mq-card">' +
      '<div class="mq-body">' +
        '<span class="mq-cat cat-malicious">⚠ Admin confirmed</span>' +
        '<p class="mq-url">' + esc(row.domain) + '</p>' +
        '<div class="mq-meta">' +
          '<div>Last confirmed: <b>' + esc(formatLocal(row.lastReportedAt)) + '</b></div>' +
          '<div>Confirmed URLs: <b>' + esc(row.reports || 1) + '</b></div>' +
        '</div>' +
      '</div>' +
    '</div>';
  }
  function showState(message, isError) {
    grid.style.display = "none";
    stateEl.style.display = "";
    stateEl.className = "mq-state" + (isError ? " error" : "");
    stateEl.textContent = message;
  }
  function renderStats(stats) {
    if (!stats || !statsEl) return;
    statTotal.textContent = (stats.totalDomains || 0).toLocaleString();
    statReports.textContent = (stats.totalReports || 0).toLocaleString();
    statUpdated.textContent = stats.lastUpdated ? formatLocal(stats.lastUpdated) : "—";
    statsEl.classList.remove("mq-initially-hidden");
    statsEl.style.display = "";
  }
  function render(data) {
    var entries = (data && data.entries) || [];
    state.total = data.total || 0;
    state.page = data.page || 1;
    state.totalPages = data.totalPages || 1;
    renderStats(data && data.stats);

    countEl.textContent = state.total + (state.total === 1 ? " domain" : " domains") +
      (state.query ? " matching “" + state.query + "”" : "");

    if (!entries.length) {
      if (state.query) {
        showState("No confirmed domains match your search.", false);
      } else {
        showState("No public domain indicators are available yet.", false);
      }
    } else {
      stateEl.style.display = "none";
      grid.style.display = "";
      grid.innerHTML = entries.map(cardHtml).join("");
    }

    pageInfo.textContent = "Page " + state.page + " of " + state.totalPages;
    prevBtn.disabled = state.loading || state.page <= 1;
    nextBtn.disabled = state.loading || state.page >= state.totalPages;
  }
  function load(page) {
    if (state.loading) return;
    state.loading = true;
    prevBtn.disabled = true;
    nextBtn.disabled = true;
    var url = "/api/malicious-qr?page=" + encodeURIComponent(page) +
      "&limit=" + encodeURIComponent(LIMIT) +
      "&q=" + encodeURIComponent(state.query);
    fetch(url, { credentials: "same-origin", headers: { "Accept": "application/json" } })
      .then(function (r) { if (!r.ok) throw new Error("bad status"); return r.json(); })
      .then(function (data) { state.loading = false; render(data); })
      .catch(function () {
        state.loading = false;
        showState("Could not load the threat database. Please try again.", true);
        prevBtn.disabled = state.page <= 1;
        nextBtn.disabled = state.page >= state.totalPages;
      });
  }

  prevBtn.addEventListener("click", function () { if (state.page > 1) load(state.page - 1); });
  nextBtn.addEventListener("click", function () { if (state.page < state.totalPages) load(state.page + 1); });

  var debounce;
  searchEl.addEventListener("input", function () {
    window.clearTimeout(debounce);
    debounce = window.setTimeout(function () {
      state.query = searchEl.value.trim();
      load(1);
    }, 300);
  });

  showState("Loading the threat database…", false);
  load(1);
})();
