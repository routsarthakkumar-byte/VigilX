
    const authPanel = document.getElementById("authPanel");
    const dashboard = document.getElementById("dashboard");
    const loginForm = document.getElementById("loginForm");
    const signupForm = document.getElementById("signupForm");
    const loginTab = document.getElementById("loginTab");
    const signupTab = document.getElementById("signupTab");
    const message = document.getElementById("message");

    function showMessage(text, type = "error") {
      message.textContent = text;
      message.className = "message " + type;
    }

    function switchForm(mode) {
      const loginMode = mode === "login";
      loginForm.hidden = !loginMode;
      signupForm.hidden = loginMode;
      loginTab.classList.toggle("active", loginMode);
      signupTab.classList.toggle("active", !loginMode);
      showMessage("");
    }

    async function apiRequest(path, options = {}) {
      const response = await fetch(path, {
        ...options,
        credentials: "same-origin",
        headers: {
          ...(options.body ? { "Content-Type": "application/json" } : {}),
          ...options.headers
        }
      });

      const text = await response.text();
      let data = {};
      try { data = JSON.parse(text); } catch {}

      if (!response.ok) {
        throw new Error(data.error || data.message || `Request failed (${response.status})`);
      }
      return data;
    }

    async function loadDashboard(username) {
      // Always verify the current identity and role using the session.
      const current = await apiRequest("/api/auth/me");
      const role = String(current.role || "").toLowerCase();
      const isAdmin = role === "admin";

      document.getElementById("welcome").textContent =
        "Welcome, " + (current.username || username || "authenticated user") +
        " | Role: " + (current.role || "Unknown");

      authPanel.hidden = true;
      dashboard.hidden = false;

      const messageBox = document.getElementById("dashboardMessage");
      messageBox.textContent = "";

      // Hide Admin-only sections for Employee and Guest accounts.
      const adminSections = [
        ["Registered users", "userList"],
        ["Available resources", "resourceList"],
        ["Recent security logs", "securityLogList"],
        ["Security alerts", "securityAlertList"]
      ];

      for (const [headingText, elementId] of adminSections) {
        const element = document.getElementById(elementId);
        const heading = [...dashboard.querySelectorAll("h3")]
          .find(item => item.textContent.trim() === headingText);

        if (heading) heading.hidden = !isAdmin;
        if (element) element.hidden = !isAdmin;
      }

      if (isAdmin) {
        await loadAdminDashboardData();
      } else {
        messageBox.textContent =
          "User portal ready. Enter a resource ID below to test your access. " +
          "Administrative logs and user management are available only to Admin.";
      }
    }

    async function loadAdminDashboardData() {
      const userList = document.getElementById("userList");
      userList.replaceChildren();

      try {
        const data = await apiRequest("/api/users");
        for (const user of (data.users || [])) {
          const row = document.createElement("div");
          row.className = "user-row";
          row.textContent = `${user.username} — ${user.role}`;
          userList.appendChild(row);
        }
        if (!userList.childElementCount) {
          userList.textContent = "No users returned by the backend.";
        }
      } catch (error) {
        userList.textContent = "Could not load users: " + error.message;
      }

      await loadSupportingDashboardData();
    }

    async function loadSupportingDashboardData() {
      const jobs = [
        ["/api/resources", "resourceList", "resources"],
        ["/api/logs", "securityLogList", "logs"],
        ["/api/alerts", "securityAlertList", "alerts"]
      ];

      for (const [endpoint, elementId, key] of jobs) {
        const container = document.getElementById(elementId);
        try {
          const data = await apiRequest(endpoint);
          const items = Array.isArray(data[key]) ? data[key] : [];

          container.replaceChildren();

          if (items.length === 0) {
            container.textContent = "No records returned by the backend.";
            continue;
          }

          for (const item of items.slice(-10).reverse()) {
            const row = document.createElement("div");
            row.className = "user-row";
            row.textContent = typeof item === "string"
              ? item
              : Object.entries(item)
                  .map(([name, value]) => `${name}: ${value}`)
                  .join(" | ");
            container.appendChild(row);
          }
        } catch (error) {
          container.textContent = "Could not load " + key + ": " + error.message;
        }
      }
    }

    document.getElementById("accessForm").addEventListener("submit", async (event) => {
      event.preventDefault();

      const button = document.getElementById("accessButton");
      const resultBox = document.getElementById("accessResult");
      const resourceID = document.getElementById("resourceID").value.trim();

      button.disabled = true;
      resultBox.textContent = "Checking access with the backend...";

      try {
        const data = await apiRequest(
          "/api/access-test?resourceID=" + encodeURIComponent(resourceID),
          { method: "POST" }
        );

        resultBox.replaceChildren();

        const heading = document.createElement("h3");
        heading.textContent = "Access: " + data.access;
        resultBox.appendChild(heading);

        const details = [
          ["User", data.username],
          ["Role", data.role],
          ["Resource", `${data.resourceName} (ID ${data.resourceID})`],
          ["Classification", data.classification],
          ["Risk score", data.riskScore + " / 100"],
          ["Risk level", data.riskLevel],
          ["Previous denials", data.previousDenials],
          ["Decision", data.message]
        ];

        for (const [label, value] of details) {
          const row = document.createElement("p");
          row.textContent = `${label}: ${value ?? "N/A"}`;
          resultBox.appendChild(row);
        }

        await loadSupportingDashboardData();
      } catch (error) {
        resultBox.textContent = "Access test failed: " + error.message;
      } finally {
        button.disabled = false;
      }
    });

    loginTab.addEventListener("click", () => switchForm("login"));
    signupTab.addEventListener("click", () => switchForm("signup"));

    loginForm.addEventListener("submit", async (event) => {
      event.preventDefault();
      const button = loginForm.querySelector('button[type="submit"]');
      button.disabled = true;
      showMessage("Signing in...", "success");

      try {
        const result = await apiRequest("/api/auth/login", {
          method: "POST",
          body: JSON.stringify({
            username: loginForm.username.value.trim(),
            password: loginForm.password.value
          })
        });

        await loadDashboard(result.username);
      } catch (error) {
        showMessage(error.message);
      } finally {
        button.disabled = false;
      }
    });

    signupForm.addEventListener("submit", async (event) => {
      event.preventDefault();
      const button = signupForm.querySelector('button[type="submit"]');
      button.disabled = true;
      showMessage("Creating account...", "success");

      try {
        const result = await apiRequest("/api/auth/signup", {
          method: "POST",
          body: JSON.stringify({
            username: signupForm.username.value.trim(),
            password: signupForm.password.value,
            role: signupForm.role.value
          })
        });

        const createdUsername = signupForm.username.value.trim();
        signupForm.reset();
        switchForm("login");
        document.getElementById("loginUsername").value = createdUsername;
        showMessage(result.message || "Account created. Please log in.", "success");
      } catch (error) {
        showMessage(error.message);
      } finally {
        button.disabled = false;
      }
    });

    document.getElementById("logoutButton").addEventListener("click", async () => {
      const button = document.getElementById("logoutButton");
      button.disabled = true;

      try {
        await apiRequest("/api/auth/logout", { method: "POST" });
      } catch (error) {
        document.getElementById("dashboardMessage").textContent = error.message;
      } finally {
        dashboard.hidden = true;
        authPanel.hidden = false;
        loginForm.reset();
        switchForm("login");
        button.disabled = false;
      }
    });

    async function checkExistingSession() {
      try {
        await loadDashboard("");
      } catch {
        authPanel.hidden = false;
        dashboard.hidden = true;
      }
    }

    checkExistingSession();
  