/**
 * Client-side interactivity & data visualizations for Firewall Rule Engine
 */

document.addEventListener("DOMContentLoaded", function () {
    // 1. Dashboard Chart 1: Allowed vs. Denied Doughnut Chart
    const trafficCanvas = document.getElementById("trafficChart");
    if (trafficCanvas && typeof Chart !== "undefined") {
        const allowed = parseInt(trafficCanvas.dataset.allowed || "0", 10);
        const denied = parseInt(trafficCanvas.dataset.denied || "0", 10);

        new Chart(trafficCanvas, {
            type: "doughnut",
            data: {
                labels: ["Allowed Traffic", "Denied Traffic"],
                datasets: [{
                    data: [allowed, denied],
                    backgroundColor: ["rgba(16, 185, 129, 0.85)", "rgba(239, 68, 68, 0.85)"],
                    borderColor: ["#10b981", "#ef4444"],
                    borderWidth: 2,
                    hoverOffset: 8
                }]
            },
            options: {
                responsive: true,
                cutout: "66%",
                plugins: {
                    legend: {
                        position: "bottom",
                        labels: { color: "#cbd5e1", padding: 16, font: { family: "Plus Jakarta Sans" } }
                    }
                }
            }
        });
    }

    // 2. Dashboard Chart 2: Protocol Breakdown Bar Chart (TCP / UDP / ICMP)
    const protoCanvas = document.getElementById("protocolChart");
    if (protoCanvas && typeof Chart !== "undefined") {
        const tcp = parseInt(protoCanvas.dataset.tcp || "0", 10);
        const udp = parseInt(protoCanvas.dataset.udp || "0", 10);
        const icmp = parseInt(protoCanvas.dataset.icmp || "0", 10);

        new Chart(protoCanvas, {
            type: "bar",
            data: {
                labels: ["TCP", "UDP", "ICMP"],
                datasets: [{
                    label: "Packets Inspected",
                    data: [tcp, udp, icmp],
                    backgroundColor: [
                        "rgba(56, 189, 248, 0.75)",
                        "rgba(168, 85, 247, 0.75)",
                        "rgba(245, 158, 11, 0.75)"
                    ],
                    borderColor: ["#38bdf8", "#a855f7", "#f59e0b"],
                    borderWidth: 1.5,
                    borderRadius: 8
                }]
            },
            options: {
                responsive: true,
                plugins: {
                    legend: { display: false }
                },
                scales: {
                    x: {
                        ticks: { color: "#cbd5e1" },
                        grid: { color: "rgba(148, 163, 184, 0.1)" }
                    },
                    y: {
                        beginAtZero: true,
                        ticks: { color: "#cbd5e1", stepSize: 1 },
                        grid: { color: "rgba(148, 163, 184, 0.1)" }
                    }
                }
            }
        });
    }

    // 3. Login Page: Show/Hide Password & Quick Demo / SQLi Test Fillers
    const togglePwdBtn = document.getElementById("togglePassword");
    const passwordInput = document.getElementById("password");
    if (togglePwdBtn && passwordInput) {
        togglePwdBtn.addEventListener("click", function () {
            const isPwd = passwordInput.type === "password";
            passwordInput.type = isPwd ? "text" : "password";
            togglePwdBtn.innerHTML = isPwd
                ? '<i class="bi bi-eye-slash"></i>'
                : '<i class="bi bi-eye"></i>';
        });
    }

    const fillDemoBtn = document.getElementById("fillDemoBtn");
    if (fillDemoBtn) {
        fillDemoBtn.addEventListener("click", function () {
            document.getElementById("username").value = "admin";
            document.getElementById("password").value = "Admin@123";
        });
    }

    const fillSqliBtn = document.getElementById("fillSqliBtn");
    if (fillSqliBtn) {
        fillSqliBtn.addEventListener("click", function () {
            document.getElementById("username").value = "' OR '1'='1' --";
            document.getElementById("password").value = "hacked123";
        });
    }

    // 4. Simulator ICMP Port Disable Helper
    const simProtocol = document.getElementById("simProtocol");
    const simSourcePort = document.getElementById("simSourcePort");
    const simDestPort = document.getElementById("simDestPort");

    function updateSimPorts() {
        if (!simProtocol || !simSourcePort || !simDestPort) return;
        const isIcmp = simProtocol.value === "ICMP";
        simSourcePort.disabled = isIcmp;
        simDestPort.disabled = isIcmp;
        if (isIcmp) {
            simSourcePort.value = "";
            simDestPort.value = "";
            simSourcePort.placeholder = "N/A for ICMP";
            simDestPort.placeholder = "N/A for ICMP";
        } else {
            simSourcePort.placeholder = "e.g., 54321";
            simDestPort.placeholder = "e.g., 443";
        }
    }

    if (simProtocol) {
        simProtocol.addEventListener("change", updateSimPorts);
        updateSimPorts();
    }

    // 5. Rule Form ICMP Port Helper
    const ruleProtocol = document.getElementById("ruleProtocol");
    const ruleSourcePort = document.getElementById("ruleSourcePort");
    const ruleDestPort = document.getElementById("ruleDestPort");

    function updateRulePorts() {
        if (!ruleProtocol || !ruleSourcePort || !ruleDestPort) return;
        const isIcmp = ruleProtocol.value === "ICMP";
        if (isIcmp) {
            ruleSourcePort.value = "ANY";
            ruleDestPort.value = "ANY";
            ruleSourcePort.readOnly = true;
            ruleDestPort.readOnly = true;
        } else {
            ruleSourcePort.readOnly = false;
            ruleDestPort.readOnly = false;
        }
    }

    if (ruleProtocol) {
        ruleProtocol.addEventListener("change", updateRulePorts);
        updateRulePorts();
    }

    // 6. Simulator Quick Presets
    document.querySelectorAll(".preset-btn").forEach(function (btn) {
        btn.addEventListener("click", function () {
            document.getElementById("simSourceIp").value = btn.dataset.src;
            document.getElementById("simDestIp").value = btn.dataset.dst;
            document.getElementById("simProtocol").value = btn.dataset.proto;
            document.getElementById("simDirection").value = btn.dataset.dir;
            updateSimPorts();
            if (btn.dataset.proto !== "ICMP") {
                document.getElementById("simSourcePort").value = btn.dataset.sport;
                document.getElementById("simDestPort").value = btn.dataset.dport;
            }
        });
    });

    // 7. Live Instant Search Filter for Rules Table & Traffic Logs Table
    const liveSearchInput = document.getElementById("liveTableSearch");
    if (liveSearchInput) {
        liveSearchInput.addEventListener("keyup", function () {
            const query = liveSearchInput.value.toLowerCase().trim();
            document.querySelectorAll(".searchable-row").forEach(function (row) {
                const text = row.innerText.toLowerCase();
                row.style.display = text.includes(query) ? "" : "none";
            });
        });
    }
});/* Lightweight UI Polish: Staggered Card Entrance & Top Loading Bar */
/* =========================================================
   Dual Theme (Dark / White) Switcher, Spotlight & Progress Bar
   ========================================================= */
(function () {
    const savedTheme = localStorage.getItem("firewall-theme") || "dark";
    document.documentElement.setAttribute("data-theme", savedTheme);
})();

document.addEventListener("DOMContentLoaded", function () {
    // 1. Inject Dark / White Theme Toggle into Navbar (with floating fallback)
    const toggleBtn = document.createElement("button");
    toggleBtn.type = "button";
    toggleBtn.id = "themeToggleBtn";
    toggleBtn.className = "theme-toggle-btn";
    toggleBtn.setAttribute("aria-label", "Toggle Dark or Light Theme");

    function syncToggleLabel() {
        const isLight = document.documentElement.getAttribute("data-theme") === "light";
        toggleBtn.innerHTML = isLight
            ? '<i class="bi bi-moon-stars-fill"></i><span>Dark</span>'
            : '<i class="bi bi-sun-fill text-warning"></i><span>Light</span>';
    }
    syncToggleLabel();

    toggleBtn.addEventListener("click", function () {
        const current = document.documentElement.getAttribute("data-theme") || "dark";
        const next = current === "dark" ? "light" : "dark";
        document.documentElement.setAttribute("data-theme", next);
        localStorage.setItem("firewall-theme", next);
        syncToggleLabel();
    });

    const navLists = document.querySelectorAll(".navbar .navbar-nav");
    if (navLists.length > 0) {
        const li = document.createElement("li");
        li.className = "nav-item d-flex align-items-center ms-2";
        li.appendChild(toggleBtn);
        navLists[navLists.length - 1].appendChild(li);
    } else {
        const navContainer = document.querySelector(".navbar .container-fluid, .navbar .container");
        if (navContainer) {
            toggleBtn.classList.add("ms-2");
            navContainer.appendChild(toggleBtn);
        } else {
            toggleBtn.style.cssText = "position:fixed;bottom:20px;right:20px;z-index:1050;";
            document.body.appendChild(toggleBtn);
        }
    }

    // 2. Staggered Card Entrance + Subtle Mouse Spotlight Glow
    const cards = document.querySelectorAll(".soc-card, .card");
    cards.forEach(function (card, index) {
        card.style.animationDelay = Math.min(index * 60, 300) + "ms";
        card.addEventListener("mousemove", function (e) {
            const rect = card.getBoundingClientRect();
            card.style.setProperty("--mx", (e.clientX - rect.left) + "px");
            card.style.setProperty("--my", (e.clientY - rect.top) + "px");
        });
    });

    // 3. Top Navigation Progress Bar
    const bar = document.createElement("div");
    bar.id = "page-progress-bar";
    document.body.prepend(bar);

    function startProgressBar() {
        bar.style.opacity = "1";
        bar.style.width = "75%";
    }

    document.querySelectorAll("a[href]").forEach(function (link) {
        link.addEventListener("click", function (e) {
            const href = link.getAttribute("href");
            if (href && href.startsWith("/") && !link.hasAttribute("download") && !e.ctrlKey && !e.metaKey) {
                startProgressBar();
            }
        });
    });

    document.querySelectorAll("form").forEach(function (form) {
        form.addEventListener("submit", startProgressBar);
    });
});