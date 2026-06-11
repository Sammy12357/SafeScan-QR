// Scan history page. Fetches the signed-in user's past scans from the API and
// renders them as a dated list, with friendly messaging for the empty and
// not-signed-in states.
const historyList = document.getElementById("history-list");

function setHistoryMessage(message) {
  if (!historyList) return;
  const paragraph = document.createElement("p");
  paragraph.textContent = message;
  historyList.replaceChildren(paragraph);
}

function formatScanDate(value) {
  if (!value) return "Unknown time";
  const date = new Date(value);
  return Number.isNaN(date.getTime()) ? String(value) : date.toLocaleString();
}

function renderHistoryItem(item) {
  const entry = document.createElement("li");
  const link = document.createElement("a");
  const url = item.url || "";
  link.href = url || "#";
  link.target = "_blank";
  link.rel = "noopener noreferrer";
  link.textContent = url || "Unknown payload";

  const details = document.createElement("div");
  const label = document.createElement("strong");
  label.textContent = item.threat_type || item.verdict || "No threat";
  const score = Number.isFinite(Number(item.risk_score)) ? `${item.risk_score}/100` : "N/A";
  details.append(label, ` - ${score} risk score - ${formatScanDate(item.scanned_at)}`);

  entry.append(link, details);
  return entry;
}

async function loadHistory() {
  try {
    const response = await fetch("/api/history", { credentials: "same-origin" });
    if (response.status === 401) {
      if (!historyList) return;
      const paragraph = document.createElement("p");
      paragraph.append("Please ");
      const link = document.createElement("a");
      link.href = "/login";
      link.textContent = "sign in";
      paragraph.append(link, " to view your scan history.");
      historyList.replaceChildren(paragraph);
      return;
    }
    if (!response.ok) throw new Error(`History request failed: ${response.status}`);
    const data = await response.json();
    if (!Array.isArray(data)) {
      setHistoryMessage("Error loading history. Please try again later.");
      return;
    }
    if (!data.length) {
      setHistoryMessage("No scans yet. Scan a QR code to see history here.");
      return;
    }
    const list = document.createElement("ul");
    list.className = "history-list";
    data.forEach((item) => list.append(renderHistoryItem(item)));
    historyList.replaceChildren(list);
  } catch (error) {
    console.error(error);
    setHistoryMessage("Error loading history. Please try again later.");
  }
}

loadHistory();
