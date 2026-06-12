const statusPill = document.getElementById("status-pill");
const hostsBody = document.getElementById("hosts-body");
const hostsUpEl = document.getElementById("hosts-up");
const hostsTotalEl = document.getElementById("hosts-total");
const lastTargetEl = document.getElementById("last-target");
const messageEl = document.getElementById("message");
const scanLocalBtn = document.getElementById("scan-local-btn");
const refreshBtn = document.getElementById("refresh-btn");
const externalForm = document.getElementById("external-form");
const targetInput = document.getElementById("target-input");

let pollTimer = null;

async function api(path, options = {}) {
  const response = await fetch(path, {
    headers: { "Content-Type": "application/json" },
    ...options,
  });
  const data = await response.json().catch(() => ({}));
  if (!response.ok) {
    throw new Error(data.error || `Request failed (${response.status})`);
  }
  return data;
}

function setMessage(text, isError = false) {
  messageEl.textContent = text;
  messageEl.style.color = isError ? "#ef4444" : "";
}

function setStatus(status) {
  statusPill.textContent = status.charAt(0).toUpperCase() + status.slice(1);
  statusPill.className = `status-pill ${status}`;
}

function renderHosts(hosts) {
  const upCount = hosts.filter((h) => h.status === "up").length;
  hostsUpEl.textContent = String(upCount);
  hostsTotalEl.textContent = String(hosts.length);

  if (!hosts.length) {
    hostsBody.innerHTML =
      '<tr class="empty-row"><td colspan="4">No hosts discovered yet. Run a scan to get started.</td></tr>';
    return;
  }

  hostsBody.innerHTML = hosts
    .map((host) => {
      const ports = host.open_ports.length ? host.open_ports.join(", ") : "—";
      const latency = host.latency_ms != null ? `${host.latency_ms} ms` : "—";
      const badgeClass = host.status === "up" ? "up" : "down";
      return `<tr>
        <td>${host.ip}</td>
        <td><span class="badge ${badgeClass}">${host.status}</span></td>
        <td>${ports}</td>
        <td>${latency}</td>
      </tr>`;
    })
    .join("");
}

async function refreshDashboard() {
  const [hostsData, statusData] = await Promise.all([
    api("/api/hosts"),
    api("/api/status"),
  ]);

  renderHosts(hostsData.hosts || []);
  setStatus(statusData.status || "idle");

  if (hostsData.last_scan) {
    lastTargetEl.textContent = hostsData.last_scan.target;
  }

  const running = statusData.status === "running";
  scanLocalBtn.disabled = running;
  externalForm.querySelector("button").disabled = running;

  if (running && !pollTimer) {
    pollTimer = setInterval(refreshDashboard, 2000);
  } else if (!running && pollTimer) {
    clearInterval(pollTimer);
    pollTimer = null;
  }
}

async function startLocalScan() {
  setMessage("Starting local network scan…");
  const result = await api("/api/scan/local", { method: "POST" });
  setMessage(result.message);
  await refreshDashboard();
}

async function startTargetScan(target) {
  setMessage(`Starting scan for ${target}…`);
  const result = await api("/api/scan/target", {
    method: "POST",
    body: JSON.stringify({ target }),
  });
  setMessage(result.message);
  await refreshDashboard();
}

scanLocalBtn.addEventListener("click", async () => {
  try {
    await startLocalScan();
  } catch (err) {
    setMessage(err.message, true);
  }
});

refreshBtn.addEventListener("click", async () => {
  try {
    await refreshDashboard();
    setMessage("Dashboard refreshed.");
  } catch (err) {
    setMessage(err.message, true);
  }
});

externalForm.addEventListener("submit", async (event) => {
  event.preventDefault();
  const target = targetInput.value.trim();
  if (!target) return;
  try {
    await startTargetScan(target);
  } catch (err) {
    setMessage(err.message, true);
  }
});

refreshDashboard().catch((err) => setMessage(err.message, true));
