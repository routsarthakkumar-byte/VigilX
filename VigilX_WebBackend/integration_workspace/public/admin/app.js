
const $ = id => document.getElementById(id);

const refreshButton = $("refreshButton");
const testButton = $("testButton");
const accessTestForm = $("accessTestForm");
const runAccessTestButton = $("runAccessTest");

function setText(id, value) {
    const element = $(id);
    if (element) element.textContent = value;
}

async function fetchAPI(endpoint) {
    const response = await fetch(endpoint, {
        method: "GET",
        cache: "no-store"
    });

    if (!response.ok) {
        throw new Error(`${endpoint} returned HTTP ${response.status}`);
    }

    return response.json();
}

function getRecords(data, key) {
    if (Array.isArray(data)) return data;
    if (Array.isArray(data?.[key])) return data[key];
    return [];
}

function field(item, keys, index) {
    if (Array.isArray(item)) return item[index] ?? "";

    for (const key of keys) {
        if (item?.[key] !== undefined && item[key] !== null) {
            return item[key];
        }
    }

    return "—";
}

function renderTable(bodyId, rows, columnCount, emptyMessage) {
    const body = $(bodyId);
    if (!body) return;

    body.replaceChildren();

    if (!rows.length) {
        const row = document.createElement("tr");
        const cell = document.createElement("td");

        cell.colSpan = columnCount;
        cell.textContent = emptyMessage;
        row.appendChild(cell);
        body.appendChild(row);
        return;
    }

    for (const values of rows) {
        const row = document.createElement("tr");

        for (const value of values) {
            const cell = document.createElement("td");
            cell.textContent = String(value ?? "—");
            row.appendChild(cell);
        }

        body.appendChild(row);
    }
}

function populateSelect(selectId, records, getId, getLabel, placeholder) {
    const select = $(selectId);
    if (!select) return;

    const previousValue = select.value;
    select.replaceChildren();

    const firstOption = document.createElement("option");
    firstOption.value = "";
    firstOption.textContent = placeholder;
    select.appendChild(firstOption);

    for (const record of records) {
        const id = getId(record);
        if (id === "" || id === "—" || id === undefined || id === null) {
            continue;
        }

        const option = document.createElement("option");
        option.value = String(id);
        option.textContent = getLabel(record);
        select.appendChild(option);
    }

    if ([...select.options].some(option => option.value === previousValue)) {
        select.value = previousValue;
    }
}

async function loadHealth() {
    const data = await fetchAPI("/api/health");

    if (data.status !== "ok") {
        throw new Error("Unexpected health API response");
    }

    setText("backendStatus", "Online");
    setText("backendDescription", "C++ server responded successfully");
    setText("apiStatus", "Healthy");
    setText("responseStatus", "200 OK");
    setText("sidebarStatus", "Backend online");
    setText("healthResponse", JSON.stringify(data, null, 2));

    const sidebarDot = $("sidebarDot");
    if (sidebarDot) sidebarDot.className = "status-dot online";
}

async function loadStats() {
    const data = await fetchAPI("/api/stats");

    setText("totalUsers", data.totalUsers ?? "—");
    setText("totalResources", data.totalResources ?? "—");
    setText("totalLogs", data.totalLogs ?? "—");
}

async function loadAnalytics() {
    const data = await fetchAPI("/api/analytics");

    setText("failedLogins", data.failedLogins ?? "—");
    setText("successfulLogins", data.successfulLogins ?? "—");
    setText("deniedAccesses", data.deniedAccesses ?? "—");
    setText("highRiskAssessments", data.highRiskAssessments ?? "—");

    setText(
        "analyticsMessage",
        `Analytics calculated from ${data.totalEvents ?? 0} recorded events.`
    );
}

async function loadAlerts() {
    const data = await fetchAPI("/api/alerts");
    const alerts = getRecords(data, "alerts");
    const list = $("alertsList");

    if (!list) return;

    list.replaceChildren();
    setText("alertCount", `${data.totalAlerts ?? alerts.length} ALERTS`);

    if (alerts.length === 0) {
        const message = document.createElement("p");
        message.textContent = "No alerts match the current alert rules.";
        list.appendChild(message);
        return;
    }

    for (const alert of alerts) {
        const card = document.createElement("article");
        card.className = "alert-card";

        const heading = document.createElement("div");
        heading.className = "alert-heading";

        const severity = document.createElement("strong");
        severity.className = "alert-severity";
        severity.textContent = alert.severity ?? "INFO";

        const type = document.createElement("span");
        type.textContent = alert.type ?? "SECURITY EVENT";

        heading.append(severity, type);

        const description = document.createElement("p");
        description.textContent = alert.message ?? "No description provided.";

        const count = document.createElement("p");
        count.className = "alert-count";
        count.textContent = `Matching recorded events: ${alert.count ?? 0}`;

        card.append(heading, description, count);

        if (
            ["REPEATED_DENIED_ACCESS", "HIGH_RISK_ASSESSMENT"].includes(alert.type) &&
            Array.isArray(alert.affectedUsers) &&
            alert.affectedUsers.length > 0
        ) {
            const usersHeading = document.createElement("h4");
            usersHeading.textContent = "Affected users";

            const usersList = document.createElement("ul");
            usersList.className = "alert-affected-users";

            for (const user of alert.affectedUsers) {
                const item = document.createElement("li");
                item.textContent =
                    `${user.username} (${user.role}) — ${user.count} ` +
                    (alert.type === "REPEATED_DENIED_ACCESS"
                        ? "denied access attempts"
                        : "high-risk assessments");

                usersList.appendChild(item);
            }

            card.append(usersHeading, usersList);
        }

        list.appendChild(card);
    }
}

async function loadUsers() {
    const data = await fetchAPI("/api/users");
    const users = getRecords(data, "users");

    renderTable(
        "usersTableBody",
        users.map(user => [
            field(user, ["id", "userID", "userId"], 0),
            field(user, ["username", "userName"], 2),
            field(user, ["role"], 1)
        ]),
        3,
        "No users found."
    );

    setText("usersCount", `${users.length} USERS`);

    populateSelect(
        "accessUser",
        users,
        user => field(user, ["id", "userID", "userId"], 0),
        user => {
            const id = field(user, ["id", "userID", "userId"], 0);
            const username = field(user, ["username", "userName"], 2);
            const role = field(user, ["role"], 1);
            return `${username} — ${role} (ID: ${id})`;
        },
        users.length ? "Select a user" : "No users available"
    );
}

async function loadResources() {
    const data = await fetchAPI("/api/resources");
    const resources = getRecords(data, "resources");

    renderTable(
        "resourcesTableBody",
        resources.map(resource => [
            field(resource, ["id", "resourceID", "resourceId"], 0),
            field(resource, ["name", "resourceName"], 2),
            field(resource, ["classification"], 1)
        ]),
        3,
        "No resources found."
    );

    setText("resourcesCount", `${resources.length} RESOURCES`);

    populateSelect(
        "accessResource",
        resources,
        resource => field(resource, ["id", "resourceID", "resourceId"], 0),
        resource => {
            const id = field(resource, ["id", "resourceID", "resourceId"], 0);
            const name = field(resource, ["name", "resourceName"], 2);
            const classification = field(resource, ["classification"], 1);
            return `${name} — ${classification} (ID: ${id})`;
        },
        resources.length ? "Select a resource" : "No resources available"
    );
}

async function loadLogs() {
    const data = await fetchAPI("/api/logs");
    const logs = getRecords(data, "logs");

    renderTable(
        "logsTableBody",
        logs.map(log => [
            field(log, ["id", "eventID", "eventId"], 0),
            field(log, ["timestamp"], 1),
            field(log, ["username"], 2),
            field(log, ["role"], 3),
            field(log, ["action"], 4),
            field(log, ["result"], 5)
        ]),
        6,
        "No security logs found."
    );
}

function showAccessError(message) {
    const errorBox = $("accessTestError");
    if (!errorBox) return;

    errorBox.textContent = message;
    errorBox.hidden = false;
}

function clearAccessError() {
    const errorBox = $("accessTestError");
    if (!errorBox) return;

    errorBox.textContent = "";
    errorBox.hidden = true;
}

function showAccessResult(data) {
    const result = $("accessTestResult");
    if (!result) return;

    result.hidden = false;

    const allowed = data.allowed === true ||
        String(data.access ?? "").toUpperCase() === "GRANTED";

    setText(
        "accessResultDescription",
        allowed
            ? "The backend approved this access request."
            : "The backend denied this access request."
    );

    setText("accessDecision", allowed ? "GRANTED" : "DENIED");
    setText("accessRiskScore", `${data.riskScore ?? "—"} / 100`);
    setText("accessRiskLevel", data.riskLevel ?? "—");
    setText("accessPreviousDenials", data.previousDenials ?? 0);

    setText(
        "accessResultUser",
        `${data.username ?? "—"} (${data.role ?? "—"})`
    );

    setText(
        "accessResultResource",
        `${data.resourceName ?? "—"} (${data.classification ?? "—"})`
    );

    setText(
        "accessPermissionMessage",
        data.message ?? "No additional explanation provided."
    );

    const decision = $("accessDecision");
    if (decision) {
        decision.className = allowed
            ? "access-decision access-allowed"
            : "access-decision access-denied";
    }

    const riskLevel = $("accessRiskLevel");
    if (riskLevel) {
        const level = String(data.riskLevel ?? "").toUpperCase();
        riskLevel.className = `access-risk risk-${level.toLowerCase()}`;
    }
}


// Fetch a read-only preview for the currently selected simulator user/resource.
async function loadAccessPreview() {
    const userID = $("accessUser")?.value;
    const resourceID = $("accessResource")?.value;

    if (!userID || !resourceID) {
        return;
    }

    const params = new URLSearchParams({ userID, resourceID });
    const response = await fetch(`/api/access-preview?${params.toString()}`, {
        method: "GET",
        cache: "no-store"
    });

    const data = await response.json();

    if (!response.ok) {
        throw new Error(
            data.error ?? `Access preview failed (HTTP ${response.status})`
        );
    }

    // Avoid showing a stale result if the user changed selections mid-request.
    if (
        $("accessUser")?.value !== userID ||
        $("accessResource")?.value !== resourceID
    ) {
        return;
    }

    clearAccessError();
    showAccessResult(data);
}

async function runAccessTest(event) {
    event.preventDefault();
    clearAccessError();

    const userID = $("accessUser")?.value;
    const resourceID = $("accessResource")?.value;

    if (!userID || !resourceID) {
        showAccessError("Please select both a user and a resource.");
        return;
    }

    if (runAccessTestButton) {
        runAccessTestButton.disabled = true;
        runAccessTestButton.textContent = "Testing...";
    }

    const result = $("accessTestResult");
    if (result) result.hidden = true;

    try {
        const response = await fetch("/api/access-test", {
            method: "POST",
            headers: {
                "Content-Type": "application/x-www-form-urlencoded"
            },
            body: new URLSearchParams({ userID, resourceID })
        });

        const data = await response.json();

        if (!response.ok) {
            throw new Error(data.error ?? `Access test failed (HTTP ${response.status})`);
        }

        showAccessResult(data);

        const refreshTasks = [
            loadStats,
            loadAnalytics,
            loadAlerts,
            loadLogs
        ];

        const refreshResults = await Promise.allSettled(
            refreshTasks.map(task => task())
        );

        const refreshFailures = refreshResults.filter(
            item => item.status === "rejected"
        );

        if (refreshFailures.length) {
            console.warn("Some dashboard data could not refresh:", refreshFailures);
        }
    } catch (error) {
        showAccessError(
            `${error.message}. Check that the VigilX C++ server is running.`
        );
    } finally {
        if (runAccessTestButton) {
            runAccessTestButton.disabled = false;
            runAccessTestButton.textContent = "Run Access Test";
        }
    }
}

async function refreshDashboard() {
    if (refreshButton) refreshButton.disabled = true;
    if (testButton) testButton.disabled = true;

    setText("dataApiStatus", "Loading");
    setText("dataApiDescription", "Fetching data from C++ backend");
    setText("sidebarStatus", "Checking server...");

    const errorBox = $("dataError");
    if (errorBox) {
        errorBox.hidden = true;
        errorBox.textContent = "";
    }

    try {
        await loadHealth();
    } catch (error) {
        setText("backendStatus", "Offline");
        setText("backendDescription", "Could not reach the C++ server");
        setText("apiStatus", "Unavailable");
        setText("responseStatus", "Request failed");
        setText("sidebarStatus", "Backend unavailable");
        setText("healthResponse", error.message);

        const sidebarDot = $("sidebarDot");
        if (sidebarDot) sidebarDot.className = "status-dot offline";

        setText("dataApiStatus", "Unavailable");
        setText("dataApiDescription", "Backend connection failed");

        if (errorBox) {
            errorBox.textContent = error.message;
            errorBox.hidden = false;
        }

        setText("lastChecked", new Date().toLocaleTimeString());

        if (refreshButton) refreshButton.disabled = false;
        if (testButton) testButton.disabled = false;
        return;
    }

    const tasks = [
        ["Statistics", loadStats],
        ["Analytics", loadAnalytics],
        ["Threat alerts", loadAlerts],
        ["Users", loadUsers],
        ["Resources", loadResources],
        ["Security logs", loadLogs]
    ];

    const results = await Promise.allSettled(
        tasks.map(([, task]) => task())
    );

    try {
        await loadAccessPreview();
    } catch (error) {
        console.warn("Access simulator preview could not refresh:", error);
    }

    const failures = [];

    results.forEach((result, index) => {
        if (result.status === "rejected") {
            failures.push(
                `${tasks[index][0]}: ${result.reason?.message ?? "Unknown error"}`
            );
        }
    });

    if (failures.length) {
        setText("dataApiStatus", "Partial");
        setText("dataApiDescription", "Some endpoints need attention");

        if (errorBox) {
            errorBox.textContent = failures.join("\n");
            errorBox.hidden = false;
        }
    } else {
        setText("dataApiStatus", "Connected");
        setText("dataApiDescription", "All dashboard endpoints responded");
    }

    setText("lastChecked", new Date().toLocaleTimeString());

    if (refreshButton) refreshButton.disabled = false;
    if (testButton) testButton.disabled = false;

    console.log("VigilX dashboard refresh:", results);
}

if (refreshButton) {
    refreshButton.addEventListener("click", refreshDashboard);
}

if (testButton) {
    testButton.addEventListener("click", refreshDashboard);
}

if (accessTestForm) {
    accessTestForm.addEventListener("submit", runAccessTest);
}

async function startAdminDashboard() {
    try {
        const response = await fetch("/api/auth/me", {
            method: "GET",
            cache: "no-store",
            credentials: "same-origin"
        });

        if (!response.ok) {
            window.location.replace("/");
            return;
        }

        const identity = await response.json();

        if (
            identity.authenticated !== true ||
            String(identity.role || "").toLowerCase() !== "admin"
        ) {
            window.location.replace("/");
            return;
        }

        refreshDashboard();
    } catch (error) {
        console.error("Admin authentication check failed:", error);
        window.location.replace("/");
    }
}

startAdminDashboard();

// VIGILX_AUTO_REFRESH_INTERVAL: refresh dashboard data every 5 seconds.
setInterval(() => {
    if (
        document.visibilityState === "visible" &&
        refreshButton &&
        !refreshButton.disabled
    ) {
        refreshDashboard();
    }
}, 5000);

