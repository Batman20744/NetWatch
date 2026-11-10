
// =====================================================
// NETWATCH - SECURITY OPERATIONS CENTER
// Dashboard JavaScript v1.0
// FINAL THEME: MIDNIGHT BLACK + MULTI-SHADE BLUE
// =====================================================

const API = {
    dashboard: "/api/dashboard",
    upload: "/api/upload-pcap",
    history: "/api/history"
};

let trafficChart = null;
let severityChart = null;
let timelineChart = null;

let currentAlerts = [];
let currentSource = "csv";

// =====================================================
// DOM HELPERS
// =====================================================

const $ = (id) => document.getElementById(id);

function escapeHTML(value) {
    return String(value ?? "").replace(/[&<>"']/g, char => ({
        "&": "&amp;",
        "<": "&lt;",
        ">": "&gt;",
        '"': "&quot;",
        "'": "&#039;"
    })[char]);
}

function showMessage(message, type = "success") {
    const box = $("messageBox");

    box.textContent = message;
    box.className = `message ${type}`;

    window.scrollTo({
        top: 0,
        behavior: "smooth"
    });

    clearTimeout(showMessage.timer);

    showMessage.timer = setTimeout(() => {
        box.className = "message";
    }, 5000);
}

async function fetchJSON(url, options = {}) {
    const response = await fetch(url, options);

    let data;

    try {
        data = await response.json();
    } catch {
        throw new Error("Invalid server response.");
    }

    if (!response.ok) {
        throw new Error(
            data.error || `HTTP Error ${response.status}`
        );
    }

    return data;
}

// =====================================================
// LOAD DASHBOARD
// =====================================================

async function loadDashboard(source = "csv", path = null) {
    let url = `${API.dashboard}?source=${encodeURIComponent(source)}`;

    if (path) {
        url += `&path=${encodeURIComponent(path)}`;
    }

    const data = await fetchJSON(url);

    currentSource = source;
    currentAlerts = data.alerts || [];

    updateStatistics(data);
    updateTrafficChart(data.traffic_chart || []);
    updateSeverityChart(data);
    updateTimelineChart(data.timeline || []);

    renderAlerts(currentAlerts);

    return data;
}

// =====================================================
// STATISTICS CARDS
// =====================================================

function updateStatistics(data) {
    // Display actual packet count when available.
    // Fall back to traffic records for older API responses.
    $("totalRecords").textContent =
        Number(
            data.total_packets ?? data.total_records ?? 0
        ).toLocaleString();

    $("totalAlerts").textContent =
        Number(data.total_alerts || 0).toLocaleString();

    $("highAlerts").textContent =
        Number(data.high_alerts || 0).toLocaleString();

    $("mediumAlerts").textContent =
        Number(data.medium_alerts || 0).toLocaleString();
}

// =====================================================
// GLOBAL CHART CONFIGURATION
// =====================================================

Chart.defaults.color = "#91A8C8";
Chart.defaults.font.family = "Inter, sans-serif";

const chartOptions = {
    responsive: true,
    maintainAspectRatio: false,

    plugins: {
        legend: {
            labels: {
                color: "#BFDBFE",
                usePointStyle: true,
                padding: 18
            }
        }
    }
};

// =====================================================
// TRAFFIC DISTRIBUTION BAR CHART
// MULTI-SHADE BLUE
// =====================================================

function updateTrafficChart(records) {
    if (trafficChart) {
        trafficChart.destroy();
    }

    trafficChart = new Chart($("trafficChart"), {
        type: "bar",

        data: {
            labels: records.map(item => item.source_ip),

            datasets: [{
                label: "Bytes Sent",

                data: records.map(item => item.bytes_sent),

                backgroundColor: [
                    "#1D4ED8",
                    "#2563EB",
                    "#3B82F6",
                    "#60A5FA",
                    "#818CF8",
                    "#93C5FD",
                    "#BFDBFE"
                ],

                borderRadius: 6,
                borderSkipped: false
            }]
        },

        options: {
            ...chartOptions,

            scales: {
                x: {
                    ticks: {
                        color: "#91A8C8"
                    },

                    grid: {
                        display: false
                    }
                },

                y: {
                    beginAtZero: true,

                    ticks: {
                        color: "#91A8C8"
                    },

                    grid: {
                        color: "rgba(96,165,250,0.12)"
                    }
                }
            }
        }
    });
}

// =====================================================
// THREAT SEVERITY DOUGHNUT CHART
// THREE DIFFERENT SHADES OF BLUE
// =====================================================

function updateSeverityChart(data) {
    const high = Number(data.high_alerts || 0);
    const medium = Number(data.medium_alerts || 0);

    const low = Math.max(
        0,
        Number(data.total_alerts || 0) - high - medium
    );

    if (severityChart) {
        severityChart.destroy();
    }

    severityChart = new Chart($("severityChart"), {
        type: "doughnut",

        data: {
            labels: ["High", "Medium", "Low"],

            datasets: [{
                data: [high, medium, low],

                backgroundColor: [
                    "#1E40AF",
                    "#3B82F6",
                    "#93C5FD"
                ],

                borderColor: "#101B30",
                borderWidth: 4,
                hoverOffset: 10
            }]
        },

        options: {
            ...chartOptions,
            cutout: "68%"
        }
    });
}

// =====================================================
// NETWORK ACTIVITY TIMELINE
// BLUE + LIGHT BLUE
// =====================================================

function updateTimelineChart(timeline) {
    if (timelineChart) {
        timelineChart.destroy();
    }

    timelineChart = new Chart($("timelineChart"), {
        type: "line",

        data: {
            labels: timeline.map(item => {
                const date = new Date(item.timestamp);

                return isNaN(date.getTime())
                    ? item.timestamp
                    : date.toLocaleTimeString();
            }),

            datasets: [
                {
                    label: "Traffic Records",

                    data: timeline.map(item =>
                        Number(item.traffic_records || 0)
                    ),

                    borderColor: "#3B82F6",

                    backgroundColor:
                        "rgba(59,130,246,0.15)",

                    pointBackgroundColor: "#60A5FA",
                    pointBorderColor: "#3B82F6",

                    pointRadius: 3,
                    pointHoverRadius: 6,

                    fill: true,
                    tension: 0.35
                },

                {
                    label: "Security Alerts",

                    data: timeline.map(item =>
                        Number(item.alerts || 0)
                    ),

                    borderColor: "#93C5FD",

                    backgroundColor:
                        "rgba(147,197,253,0.10)",

                    pointBackgroundColor: "#BFDBFE",
                    pointBorderColor: "#93C5FD",

                    pointRadius: 3,
                    pointHoverRadius: 6,

                    fill: false,
                    tension: 0.35
                }
            ]
        },

        options: {
            ...chartOptions,

            scales: {
                x: {
                    ticks: {
                        color: "#91A8C8"
                    },

                    grid: {
                        display: false
                    }
                },

                y: {
                    beginAtZero: true,

                    ticks: {
                        color: "#91A8C8",
                        precision: 0
                    },

                    grid: {
                        color: "rgba(96,165,250,0.12)"
                    }
                }
            }
        }
    });
}

// =====================================================
// SECURITY ALERTS TABLE
// =====================================================

function renderAlerts(alerts) {
    const table = $("alertsTable");

    if (!alerts.length) {
        table.innerHTML = `
            <tr>
                <td colspan="8" style="text-align:center">
                    No security alerts detected.
                </td>
            </tr>
        `;

        return;
    }

    table.innerHTML = alerts.map(alert => {
        const severity = String(
            alert.severity || "Low"
        ).toLowerCase();

        return `
            <tr>

                <td class="mono">
                    ${escapeHTML(alert.timestamp || "-")}
                </td>

                <td class="mono">
                    ${escapeHTML(alert.source_ip)}
                </td>

                <td class="mono">
                    ${escapeHTML(alert.destination_ip)}
                </td>

                <td>
                    ${escapeHTML(alert.destination_port)}
                </td>

                <td>
                    ${escapeHTML(alert.protocol)}
                </td>

                <td>
                    ${escapeHTML(alert.packet_count)}
                </td>

                <td>
                    <span class="severity ${severity}">
                        ${escapeHTML(alert.severity)}
                    </span>
                </td>

                <td>
                    ${escapeHTML(alert.alert_reasons)}
                </td>

            </tr>
        `;
    }).join("");
}

// =====================================================
// ALERT SEARCH AND FILTER
// =====================================================

function filterAlerts() {
    const search = $("alertSearch").value.toLowerCase();

    const severity = $("severityFilter").value;

    const filtered = currentAlerts.filter(alert => {

        const matchesSeverity =
            severity === "all" ||
            String(alert.severity).toLowerCase() ===
            severity.toLowerCase();

        const searchable = [
            alert.source_ip,
            alert.destination_ip,
            alert.destination_port,
            alert.protocol,
            alert.alert_reasons
        ].join(" ").toLowerCase();

        return matchesSeverity &&
            searchable.includes(search);
    });

    renderAlerts(filtered);
}

// =====================================================
// PCAP UPLOAD AND ANALYSIS
// =====================================================

async function uploadPCAP(event) {
    event.preventDefault();

    const fileInput = $("pcapFile");

    const file = fileInput.files[0];

    if (!file) {
        showMessage(
            "Please select a PCAP file.",
            "error"
        );

        return;
    }

    if (!/\.(pcap|pcapng)$/i.test(file.name)) {
        showMessage(
            "Only PCAP and PCAPNG files are supported.",
            "error"
        );

        return;
    }

    if (file.size > 10 * 1024 * 1024) {
        showMessage(
            "Maximum upload size is 10 MB.",
            "error"
        );

        return;
    }

    const button = event.submitter;

    const originalText = button?.innerHTML;

    try {
        if (button) {
            button.disabled = true;
            button.textContent = "Analyzing...";
        }

        const formData = new FormData();

        formData.append("file", file);

        const data = await fetchJSON(API.upload, {
            method: "POST",
            body: formData
        });

        currentSource = "uploaded-pcap";

        currentAlerts = data.alerts || [];

        updateStatistics(data);

        updateTrafficChart(
            data.traffic_chart || []
        );

        updateSeverityChart(data);

        updateTimelineChart(
            data.timeline || []
        );

        renderAlerts(currentAlerts);

        await loadHistory();

        showMessage(
            `PCAP analysis completed. ${data.total_alerts} alerts detected.`
        );

        fileInput.value = "";

        $("alerts").scrollIntoView({
            behavior: "smooth"
        });

    } catch (error) {
        showMessage(
            "PCAP analysis failed: " + error.message,
            "error"
        );

    } finally {
        if (button) {
            button.disabled = false;
            button.innerHTML = originalText;
        }
    }
}

// =====================================================
// ANALYSIS HISTORY
// SQLITE DATABASE
// =====================================================

async function loadHistory() {
    try {
        const data = await fetchJSON(
            `${API.history}?limit=50`
        );

        const history = data.history || [];

        const table = $("historyTable");

        if (!history.length) {
            table.innerHTML = `
                <tr>
                    <td colspan="6" style="text-align:center">
                        No analysis history available.
                    </td>
                </tr>
            `;

            return;
        }

        table.innerHTML = history.map(item => `
            <tr>

                <td>
                    #${escapeHTML(item.id)}
                </td>

                <td>
                    ${escapeHTML(item.filename || "-")}
                </td>

                <td>
                    ${escapeHTML(item.analysis_type || "-")}
                </td>

                <td>
                    ${escapeHTML(item.total_records ?? "-")}
                </td>

                <td>
                    ${escapeHTML(item.alert_count ?? "-")}
                </td>

                <td>
                    <button
                        class="history-action"
                        data-history-id="${escapeHTML(item.id)}">

                        View Details

                    </button>
                </td>

            </tr>
        `).join("");

    } catch (error) {
        console.error(
            "History error:",
            error
        );

        $("historyTable").innerHTML = `
            <tr>
                <td colspan="6">
                    Unable to load analysis history.
                </td>
            </tr>
        `;
    }
}

// =====================================================
// VIEW SAVED HISTORY DETAILS
// =====================================================

async function viewHistory(id) {
    try {
        const data = await fetchJSON(
            `${API.history}/${encodeURIComponent(id)}`
        );

        currentAlerts = data.alerts || [];

        renderAlerts(currentAlerts);

        $("alertSearch").value = "";
        $("severityFilter").value = "all";

        showMessage(
            `Loaded analysis #${id}: ${currentAlerts.length} saved alerts.`
        );

        $("alerts").scrollIntoView({
            behavior: "smooth"
        });

    } catch (error) {
        showMessage(
            "Could not retrieve history: " + error.message,
            "error"
        );
    }
}

// =====================================================
// SIDEBAR NAVIGATION
// =====================================================

function setupNavigation() {
    document.querySelectorAll(".nav-link").forEach(link => {

        link.addEventListener("click", () => {

            document.querySelectorAll(".nav-link")
                .forEach(item =>
                    item.classList.remove("active")
                );

            link.classList.add("active");

            $("sidebar").classList.remove("open");
        });

    });

    $("menuToggle").addEventListener("click", () => {
        $("sidebar").classList.toggle("open");
    });
}

// =====================================================
// EVENT LISTENERS
// =====================================================

function setupEvents() {

    // REFRESH DASHBOARD

    $("refreshBtn").addEventListener(
        "click",
        async () => {

            try {
                if (currentSource === "uploaded-pcap") {
                    showMessage(
                        "Upload the PCAP again to refresh its analysis.",
                        "error"
                    );

                    return;
                }

                await loadDashboard("csv");

                await loadHistory();

                showMessage(
                    "Dashboard refreshed successfully."
                );

            } catch (error) {
                showMessage(
                    error.message,
                    "error"
                );
            }
        }
    );

    // ANALYZE SAMPLE CSV

    $("analyzeCsvBtn").addEventListener(
        "click",
        async () => {

            try {
                await loadDashboard("csv");

                await loadHistory();

                showMessage(
                    "Sample CSV analysis completed."
                );

            } catch (error) {
                showMessage(
                    error.message,
                    "error"
                );
            }
        }
    );

    // PCAP UPLOAD

    $("pcapForm").addEventListener(
        "submit",
        uploadPCAP
    );

    // ALERT SEARCH

    $("alertSearch").addEventListener(
        "input",
        filterAlerts
    );

    // SEVERITY FILTER

    $("severityFilter").addEventListener(
        "change",
        filterAlerts
    );

    // REFRESH HISTORY

    $("refreshHistoryBtn").addEventListener(
        "click",
        loadHistory
    );

    // LIVE CAPTURE AND REPUTATION

    $("startLiveBtn").addEventListener(
        "click",
        startLiveCapture
    );

    $("stopLiveBtn").addEventListener(
        "click",
        stopLiveCapture
    );

    $("refreshLiveBtn").addEventListener(
        "click",
        refreshLiveStatus
    );

    $("reputationForm").addEventListener(
        "submit",
        checkReputation
    );

    // VIEW HISTORY DETAILS

    $("historyTable").addEventListener(
        "click",
        event => {

            const button = event.target.closest(
                "[data-history-id]"
            );

            if (button) {
                viewHistory(
                    button.dataset.historyId
                );
            }
        }
    );
}

// =====================================================
// INITIALIZE DASHBOARD
// =====================================================

document.addEventListener(
    "DOMContentLoaded",
    async () => {

        setupNavigation();

        setupEvents();
        refreshLiveStatus();
        window.setInterval(refreshLiveStatus, 2000);

        try {
            await loadDashboard("csv");

            await loadHistory();

            console.log(
                "NETWATCH SECURITY OPERATIONS CENTER INITIALIZED"
            );

        } catch (error) {

            console.error(
                "NetWatch initialization failed:",
                error
            );
        }
    }
);

// =====================================================
// LIVE PACKET MONITORING
// =====================================================

function formatBytes(value) {
    const bytes = Number(value || 0);

    if (bytes < 1024) return `${bytes} B`;

    if (bytes < 1024 * 1024) {
        return `${(bytes / 1024).toFixed(1)} KB`;
    }

    return `${(bytes / (1024 * 1024)).toFixed(2)} MB`;
}

function renderLiveStatus(data) {
    $("liveState").textContent =
        data.running ? "CAPTURING" : "STOPPED";

    $("livePackets").textContent =
        Number(data.packets || 0).toLocaleString();

    $("liveBytes").textContent =
        formatBytes(data.bytes);

    $("liveAlerts").textContent =
        (data.recent_alerts || []).length;

    $("startLiveBtn").disabled =
        Boolean(data.running);

    $("stopLiveBtn").disabled =
        !data.running;

    const rows = data.recent_alerts || [];

    $("liveEventsTable").innerHTML = rows.length
        ? rows.slice(0, 30).map(item => `
            <tr>
                <td>${escapeHTML(item.timestamp)}</td>
                <td class="mono">${escapeHTML(item.source_ip)}</td>
                <td class="mono">${escapeHTML(item.destination_ip)}</td>
                <td>${escapeHTML(item.protocol)}</td>
                <td>${escapeHTML(item.destination_port)}</td>
                <td>${escapeHTML(item.alert_reasons)}</td>
            </tr>
        `).join("")
        : '<tr><td colspan="6" style="text-align:center">No live security events detected.</td></tr>';

    if (data.error) {
        showMessage(data.error, "error");
    }
}

async function refreshLiveStatus() {
    try {
        const data = await fetchJSON("/api/live/status");
        renderLiveStatus(data);
    } catch (error) {
        console.error("Live status error:", error);
    }
}

async function startLiveCapture() {
    try {
        const interfaceName =
            $("liveInterface").value.trim();

        const data = await fetchJSON("/api/live/start", {
            method: "POST",
            headers: {
                "Content-Type": "application/json"
            },
            body: JSON.stringify({
                interface: interfaceName
            })
        });

        renderLiveStatus(data);

        showMessage("Live packet capture started.");

    } catch (error) {
        showMessage(error.message, "error");
    }
}

async function stopLiveCapture() {
    try {
        const data = await fetchJSON(
            "/api/live/stop",
            {method: "POST"}
        );

        renderLiveStatus(data);

        showMessage("Live packet capture stopped.");

    } catch (error) {
        showMessage(error.message, "error");
    }
}

// =====================================================
// IP REPUTATION LOOKUP
// =====================================================

async function checkReputation(event) {
    event.preventDefault();

    const ip = $("reputationIP").value.trim();
    const button = $("checkReputationBtn");
    const resultBox = $("reputationResult");

    button.disabled = true;
    resultBox.textContent = "Checking AbuseIPDB...";

    try {
        const data = await fetchJSON("/api/reputation", {
            method: "POST",
            headers: {
                "Content-Type": "application/json"
            },
            body: JSON.stringify({ip})
        });

        const riskClass =
            String(data.risk || "Low").toLowerCase();

        resultBox.innerHTML = `
            <div class="stats-grid">

                <div class="stat-card">
                    <div class="stat-label">IP Address</div>
                    <div class="stat-value" style="font-size:20px">
                        ${escapeHTML(data.ip)}
                    </div>
                </div>

                <div class="stat-card">
                    <div class="stat-label">Abuse Confidence</div>
                    <div class="stat-value">
                        ${escapeHTML(data.abuse_confidence_score)}%
                    </div>
                </div>

                <div class="stat-card">
                    <div class="stat-label">Risk Level</div>
                    <div class="stat-value ${riskClass}">
                        ${escapeHTML(data.risk)}
                    </div>
                </div>

                <div class="stat-card">
                    <div class="stat-label">Total Reports</div>
                    <div class="stat-value">
                        ${escapeHTML(data.total_reports)}
                    </div>
                </div>

            </div>

            <p style="margin-top:14px">
                Country: ${escapeHTML(data.country_code)}
                · ISP: ${escapeHTML(data.isp)}
                · Domain: ${escapeHTML(data.domain)}
                · Tor: ${data.is_tor ? "Yes" : "No"}
            </p>

            <small>
                Source: AbuseIPDB${data.cached ? " (cached result)" : ""}.
                Reputation scores are indicators, not proof of malicious activity.
            </small>
        `;

    } catch (error) {
        resultBox.textContent = error.message;
        showMessage(error.message, "error");

    } finally {
        button.disabled = false;
    }
}
