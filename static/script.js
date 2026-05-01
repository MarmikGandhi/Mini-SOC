const state = {
    latestPackets: [],
    alerts: [],
    events: [],
    overview: null,
};

const metricTotalAlerts = document.getElementById("metric-total-alerts");
const metricHighAlerts = document.getElementById("metric-high-alerts");
const metricPackets = document.getElementById("metric-packets");
const metricScans = document.getElementById("metric-scans");
const collectionMode = document.getElementById("collection-mode");
const lastActivity = document.getElementById("last-activity");
const alertsTable = document.getElementById("alerts-table");
const eventsFeed = document.getElementById("events-feed");
const severityBreakdown = document.getElementById("severity-breakdown");
const trafficChart = document.getElementById("traffic-chart");
const trafficEmpty = document.getElementById("traffic-empty");
const scanResult = document.getElementById("scan-result");
const encryptResult = document.getElementById("encrypt-result");
const themeToggle = document.getElementById("theme-toggle");

function applyTheme(theme) {
    document.body.dataset.theme = theme;
    themeToggle?.setAttribute("aria-pressed", theme === "dark" ? "true" : "false");
}

function initializeTheme() {
    const storedTheme = localStorage.getItem("mini-soc-theme");
    const prefersDark = window.matchMedia("(prefers-color-scheme: dark)").matches;
    const theme = storedTheme || (prefersDark ? "dark" : "light");
    applyTheme(theme);
}

function toggleTheme() {
    const nextTheme = document.body.dataset.theme === "dark" ? "light" : "dark";
    localStorage.setItem("mini-soc-theme", nextTheme);
    applyTheme(nextTheme);
}

function escapeHtml(value) {
    return String(value ?? "").replace(/[&<>"']/g, (char) => ({
        "&": "&amp;",
        "<": "&lt;",
        ">": "&gt;",
        '"': "&quot;",
        "'": "&#39;",
    }[char]));
}

function severityClass(severity) {
    return `severity-${(severity || "low").toLowerCase()}`;
}

function formatTime(value) {
    if (!value) {
        return "Unknown";
    }

    const date = new Date(value);
    if (Number.isNaN(date.getTime())) {
        return value;
    }

    return date.toLocaleString();
}

function renderMetrics(overview) {
    const metrics = overview?.metrics || {};
    metricTotalAlerts.textContent = metrics.total_alerts || 0;
    metricHighAlerts.textContent = (metrics.high_alerts || 0) + (metrics.critical_alerts || 0);
    metricPackets.textContent = metrics.recent_packets || 0;
    metricScans.textContent = metrics.scan_runs || 0;
}

function renderSeverityBreakdown(overview) {
    const breakdown = overview?.severity_breakdown || {};
    const entries = Object.entries(breakdown);

    if (!entries.length) {
        severityBreakdown.innerHTML = `<div class="empty-state">No alerts have been generated yet.</div>`;
        return;
    }

    severityBreakdown.innerHTML = entries
        .sort((a, b) => b[1] - a[1])
        .map(([severity, count]) => `
            <div class="severity-item">
                <span>${severity}</span>
                <span class="severity-badge ${severityClass(severity)}">${count}</span>
            </div>
        `)
        .join("");
}

function renderAlerts(alerts) {
    if (!alerts.length) {
        alertsTable.innerHTML = `<tr><td colspan="5" class="muted">No alerts yet. Start monitoring to populate this list.</td></tr>`;
        return;
    }

    alertsTable.innerHTML = alerts
        .slice(0, 10)
        .map((alert) => `
            <tr>
                <td><span class="table-badge ${severityClass(alert.severity)}">${alert.severity}</span></td>
                <td>${alert.type || "Alert"}</td>
                <td>${alert.source || "-"}</td>
                <td>${alert.message || "-"}</td>
                <td>${formatTime(alert.timestamp)}</td>
            </tr>
        `)
        .join("");
}

function describeEvent(event) {
    const details = event.details || {};

    if (event.event_type === "monitor_run") {
        return `${details.packet_count || 0} packets reviewed, ${details.generated_alerts || 0} alerts generated.`;
    }

    if (event.event_type === "scan") {
        return `${details.target || "Target"} scanned with risk score ${details.risk_score ?? "n/a"}.`;
    }

    if (event.event_type === "file_encryption") {
        return `${details.filename || "File"} encrypted as ${details.output_name || "artifact"}.`;
    }

    if (event.event_type === "alert") {
        return details.message || "Alert recorded.";
    }

    return JSON.stringify(details);
}

function renderEvents(events) {
    if (!events.length) {
        eventsFeed.innerHTML = `<div class="empty-state">No logged events yet.</div>`;
        return;
    }

    eventsFeed.innerHTML = events
        .slice(0, 8)
        .map((event) => `
            <div class="event-item">
                <div class="event-item-top">
                    <strong>${event.event_type.replace(/_/g, " ")}</strong>
                    <span class="event-time">${formatTime(event.timestamp)}</span>
                </div>
                <p>${describeEvent(event)}</p>
            </div>
        `)
        .join("");
}

function renderTrafficChart(packets) {
    if (!packets.length) {
        trafficChart.innerHTML = "";
        trafficEmpty.style.display = "block";
        return;
    }

    trafficEmpty.style.display = "none";
    const recentPackets = packets.slice(-12);
    const maxPackets = Math.max(...recentPackets.map((packet) => packet.packet_size || 0), 1);

    trafficChart.innerHTML = recentPackets
        .map((packet, index) => {
            const height = Math.max(18, Math.round(((packet.packet_size || 0) / maxPackets) * 170));
            return `
                <div class="traffic-bar" title="${packet.protocol_name} ${packet.service}">
                    <span class="traffic-bar-value">${packet.packet_size || 0}</span>
                    <div class="traffic-bar-fill" style="height:${height}px"></div>
                    <span class="traffic-bar-label">${index + 1}</span>
                </div>
            `;
        })
        .join("");
}

function setHeroStatus(mode, timestamp) {
    collectionMode.textContent = mode || "Awaiting run";
    lastActivity.textContent = timestamp ? formatTime(timestamp) : "Not yet recorded";
}

async function loadDashboard() {
    const [overviewResponse, alertsResponse, eventsResponse] = await Promise.all([
        fetch("/api/overview"),
        fetch("/api/alerts"),
        fetch("/api/events"),
    ]);

    state.overview = await overviewResponse.json();
    state.alerts = await alertsResponse.json();
    state.events = await eventsResponse.json();

    renderMetrics(state.overview);
    renderSeverityBreakdown(state.overview);
    renderAlerts(state.alerts);
    renderEvents(state.events);

    const latestEvent = state.events[0];
    setHeroStatus(
        latestEvent?.details?.mode || state.latestPackets[0]?.collection_mode,
        latestEvent?.timestamp,
    );
}

async function runMonitoring(mode) {
    const button = mode === "auto" ? document.getElementById("run-auto") : document.getElementById("run-simulated");
    const originalLabel = button.textContent;
    button.textContent = "Running...";
    button.disabled = true;

    try {
        const response = await fetch("/api/monitor/run", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ mode }),
        });

        const data = await response.json();
        state.latestPackets = data.packets || [];
        renderTrafficChart(state.latestPackets);
        setHeroStatus(state.latestPackets[0]?.collection_mode || mode, new Date().toISOString());
        await loadDashboard();
    } finally {
        button.textContent = originalLabel;
        button.disabled = false;
    }
}

async function handleScan(event) {
    event.preventDefault();
    const url = document.getElementById("scan-url").value.trim();

    if (!url) {
        scanResult.innerHTML = "<strong>Scan error</strong><p>Enter a target URL first.</p>";
        return;
    }

    scanResult.innerHTML = "<strong>Scanning...</strong><p>Running lightweight exposure checks.</p>";

    const response = await fetch("/api/scan", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ url }),
    });
    const data = await response.json();

    if (!data.ok) {
        scanResult.innerHTML = `<strong>Scan failed</strong><p>${data.error || "Unknown error."}</p>`;
        return;
    }

    const findings = data.findings?.length
        ? `<ul class="finding-list">${data.findings.map((finding) => `<li>${finding.severity.toUpperCase()}: ${finding.title}</li>`).join("")}</ul>`
        : "<p>No obvious issues were found in this lightweight scan.</p>";

    const recommendations = data.recommendations?.length
        ? `<ul class="recommendation-list">${data.recommendations.map((item) => `<li>${item}</li>`).join("")}</ul>`
        : "";

    scanResult.innerHTML = `
        <strong>${data.summary}</strong>
        <p>Target: ${data.target}</p>
        <p>Status code: ${data.status_code} | Risk score: ${data.risk_score}</p>
        ${findings}
        ${recommendations}
    `;

    await loadDashboard();
}

async function handleEncrypt(event) {
    event.preventDefault();
    const fileInput = document.getElementById("encrypt-file");
    const file = fileInput.files[0];

    if (!file) {
        encryptResult.innerHTML = "<strong>Encryption error</strong><p>Select a file first.</p>";
        return;
    }

    const formData = new FormData();
    formData.append("file", file);
    encryptResult.innerHTML = "<strong>Encrypting...</strong><p>Protecting selected artifact.</p>";

    const response = await fetch("/api/encrypt", {
        method: "POST",
        body: formData,
    });
    const data = await response.json();

    if (!data.ok) {
        encryptResult.innerHTML = `<strong>Encryption failed</strong><p>${data.error || "Unknown error."}</p>`;
        return;
    }

    encryptResult.innerHTML = `
        <strong>${data.message}</strong>
        <p>Original file: ${escapeHtml(data.original_name)}</p>
        <p>Encrypted artifact: ${escapeHtml(data.encrypted_name)}</p>
        <p>Size: ${data.original_size} bytes -> ${data.encrypted_size} bytes</p>
        <div class="result-actions">
            <a class="ghost-button result-link" href="${escapeHtml(data.download_url || `/api/encrypt/download/${encodeURIComponent(data.encrypted_name)}`)}" download>
                Download Encrypted File
            </a>
        </div>
    `;

    await loadDashboard();
}

document.getElementById("run-auto").addEventListener("click", () => runMonitoring("auto"));
document.getElementById("run-simulated").addEventListener("click", () => runMonitoring("simulated"));
document.getElementById("refresh-data").addEventListener("click", loadDashboard);
document.getElementById("scan-form").addEventListener("submit", handleScan);
document.getElementById("encrypt-form").addEventListener("submit", handleEncrypt);
themeToggle?.addEventListener("click", toggleTheme);

initializeTheme();
loadDashboard().catch(() => {
    eventsFeed.innerHTML = `<div class="empty-state">Dashboard data could not be loaded.</div>`;
});
