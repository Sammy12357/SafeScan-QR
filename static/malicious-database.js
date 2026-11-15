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
  stateEl.className = "mq-state-host";

  var LIMIT = parseInt(grid.getAttribute("data-limit"), 10) || 20;
  var state = { page: 1, totalPages: 1, total: 0, query: "", loading: false };
  var activeController = null;
  var activeOperation = null;
  var requestSeq = 0;

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
  function showState(options, kind) {
    grid.style.display = "none";
    grid.hidden = true;
    stateEl.style.display = "";
    stateEl.hidden = false;
    if (kind === "error") UIStates.error(stateEl, options);
    else UIStates.empty(stateEl, options);
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
        showState({
          kind: "no-results",
          title: "No results for “" + state.query + "”",
          body: "Try another search or clear the filters.",
          actionLabel: "Clear search",
          action: function () { searchEl.value = ""; state.query = ""; load(1); }
        }, "empty");
      } else {
        showState({
          title: "No confirmed domains yet",
          body: "Admin-confirmed domains will appear here. You can still check a QR code before opening it.",
          actionLabel: "Scan a QR code",
          actionHref: "/#scanner"
        }, "empty");
      }
    } else {
      stateEl.style.display = "none";
      stateEl.hidden = true;
      grid.style.display = "";
      grid.hidden = false;
      grid.innerHTML = entries.map(cardHtml).join("");
    }

    pageInfo.textContent = "Page " + state.page + " of " + state.totalPages;
    prevBtn.disabled = state.loading || state.page <= 1;
    nextBtn.disabled = state.loading || state.page >= state.totalPages;
  }
  function load(page) {
    if (activeController) activeController.abort();
    if (activeOperation) activeOperation.cancel();
    var seq = ++requestSeq;
    var controller = new AbortController();
    var timedOut = false;
    var hasRows = grid.children.length > 0 && !grid.hidden;
    activeController = controller;
    state.loading = true;
    prevBtn.disabled = true;
    nextBtn.disabled = true;
    grid.setAttribute("aria-busy", "true");
    stateEl.style.display = "";
    stateEl.hidden = false;
    stateEl.replaceChildren();
    activeOperation = UIStates.loading(stateEl, {
      label: hasRows ? "Updating threat database" : "Loading threat database",
      skeletonRows: hasRows ? 0 : 3,
      compact: hasRows,
      timeoutTitle: hasRows ? "Threat database didn't update" : "Threat database didn't load",
      timeoutBody: hasRows
        ? "These are previous results and may not match your search. Try again to update them."
        : "Check your connection and try again.",
      retry: function () { load(page); },
      onTimeout: function () {
        if (seq !== requestSeq) return;
        timedOut = true;
        controller.abort();
        state.loading = false;
        grid.removeAttribute("aria-busy");
        prevBtn.disabled = state.page <= 1;
        nextBtn.disabled = state.page >= state.totalPages;
      }
    });
    var url = "/api/malicious-qr?page=" + encodeURIComponent(page) +
      "&limit=" + encodeURIComponent(LIMIT) +
      "&q=" + encodeURIComponent(state.query);
    UIStates.fetchJson(url, { credentials: "same-origin", signal: controller.signal })
      .then(function (data) {
        if (seq !== requestSeq || timedOut) return;
        if (!data || !Array.isArray(data.entries)) throw new Error("Unexpected threat database response");
        activeOperation.finish();
        state.loading = false;
        grid.removeAttribute("aria-busy");
        render(data);
      })
      .catch(function (problem) {
        if (seq !== requestSeq || timedOut) return;
        activeOperation.finish();
        state.loading = false;
        grid.removeAttribute("aria-busy");
        stateEl.style.display = "";
        stateEl.hidden = false;
        UIStates.error(stateEl, {
          title: hasRows ? "Threat database didn't update" : "Threat database didn't load",
          body: problem && problem.code === "offline"
            ? hasRows
              ? "You're offline. These are previous results and may not match your search. Reconnect to update them."
              : "You're offline. Reconnect and try again."
            : hasRows
              ? "These are previous results and may not match your search. Try again to update them."
              : "Check your connection and try again.",
          retry: function () { load(page); },
          focus: true
        });
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

  load(1);
})();
