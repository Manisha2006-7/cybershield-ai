document.addEventListener('DOMContentLoaded', () => {

    // --- 1. Dark Mode / Theme Toggle ---
    const darkModeToggle = document.getElementById('darkModeToggle');
    const currentTheme = localStorage.getItem('theme');
    
    if (currentTheme === 'dark') {
        document.documentElement.setAttribute('data-theme', 'dark');
        if (darkModeToggle) darkModeToggle.checked = true;
    }

    if (darkModeToggle) {
        darkModeToggle.addEventListener('change', (e) => {
            if (e.target.checked) {
                document.documentElement.setAttribute('data-theme', 'dark');
                localStorage.setItem('theme', 'dark');
            } else {
                document.documentElement.removeAttribute('data-theme');
                localStorage.setItem('theme', 'light');
            }
            if (window.myPieChart) window.myPieChart.update();
            if (window.myTrendChart) window.myTrendChart.update();
        });
    }

    // --- 2. Chart.js Initialization ---
    const pieCtx = document.getElementById('trafficPieChart');
    const trendCtx = document.getElementById('trendChart');

    if (pieCtx && trendCtx) {
        window.myPieChart = new Chart(pieCtx, {
            type: 'doughnut',
            data: { 
                labels: ['Normal', 'Attack'], 
                datasets: [{ 
                    data: [window.initNormal || 0, window.initAttack || 0], 
                    backgroundColor: ['#2ecc71', '#e74c3c'],
                    borderWidth: 0
                }] 
            },
            options: { responsive: true, maintainAspectRatio: false, plugins: { title: { display: true, text: "Traffic Distribution" }, legend: { position: 'bottom' } } }
        });

        window.myTrendChart = new Chart(trendCtx, {
            type: 'line',
            data: {
                labels: window.trendLabels || [],
                datasets: [{
                    label: 'Cumulative Attacks',
                    data: window.trendData || [],
                    borderColor: '#e74c3c',
                    backgroundColor: 'rgba(231, 76, 60, 0.1)',
                    fill: true,
                    tension: 0.3,
                    pointRadius: 3
                }]
            },
            options: { responsive: true, maintainAspectRatio: false, plugins: { title: { display: true, text: "Attack Trend Over Time" }, legend: { display: false } }, scales: { y: { beginAtZero: true, ticks: { precision: 0 } } } }
        });
    }

    // --- 3. Live Traffic Simulation ---
    const simBtn = document.getElementById('toggleSimBtn');
    let simInterval = null;

    if (simBtn) {
        simBtn.addEventListener('click', () => {
            if (simInterval) {
                clearInterval(simInterval);
                simInterval = null;
                simBtn.textContent = "▶ Start Live Simulation";
                simBtn.classList.replace("btn-danger", "btn-warning");
            } else {
                simBtn.textContent = "⏸ Stop Simulation";
                simBtn.classList.replace("btn-warning", "btn-danger");
                simInterval = setInterval(async () => {
                    try {
                        const response = await fetch('/simulate');
                        const result = await response.json();
                        if (result.status === 'success') updateDashboardUI(result.record, result.stats);
                    } catch (err) {
                        console.error("Simulation error:", err);
                    }
                }, 2500);
            }
        });
    }

    function updateDashboardUI(record, stats) {
        document.getElementById('totCount').textContent = stats.total;
        document.getElementById('normCount').textContent = stats.normal;
        document.getElementById('atkCount').textContent = stats.attack;

        window.myPieChart.data.datasets[0].data = [stats.normal, stats.attack];
        window.myPieChart.update();

        window.myTrendChart.data.labels = stats.trend_labels;
        window.myTrendChart.data.datasets[0].data = stats.trend_data;
        window.myTrendChart.update();

        const tbody = document.getElementById('tableBody');
        const noDataRow = document.getElementById('noDataRow');
        if (noDataRow) noDataRow.remove();

        const row = document.createElement('tr');
        if (record.severity === 'High') row.classList.add('row-high-severity');
        else if (record.result === 'Attack') row.classList.add('row-danger');

        const resultBadge = record.result === 'Attack' ? 'badge-danger' : 'badge-success';
        let sevBadge = 'badge-success';
        if (record.severity === 'Medium') sevBadge = 'badge-warning';
        if (record.severity === 'High') sevBadge = 'badge-danger';
        
        row.innerHTML = `
            <td class="text-muted">${record.timestamp}</td>
            <td><span class="badge ${resultBadge}">${record.result}</span></td>
            <td><span class="tooltip" title="Model confidence score">${record.confidence}%</span></td>
            <td><span class="badge ${sevBadge}">${record.severity}</span></td>
            <td>${record.attack_type}</td>
            <td class="text-muted">${record.reason}</td>
        `;
        
        tbody.insertBefore(row, tbody.firstChild);
        if (tbody.children.length > 15) tbody.lastChild.remove();

        if (record.result === 'Attack') {
            Toastify({
                text: `🚨 Threat Detected: ${record.attack_type}\nSeverity: ${record.severity} | Conf: ${record.confidence}%\nReason: ${record.reason}`,
                duration: 5000, gravity: "top", position: "right",
                style: { background: "#e74c3c", color: "white", borderRadius: "8px", fontWeight: "bold", boxShadow: "0 4px 12px rgba(0,0,0,0.15)" }
            }).showToast();
        }
    }

    // --- 4. Manual Packet Scan ---
    const manualForm = document.getElementById('manualForm');
    if (manualForm) {
        manualForm.addEventListener('submit', async (e) => {
            e.preventDefault();
            const btn = document.getElementById('btnManual');
            const originalText = btn.textContent;
            btn.textContent = "Scanning Packet...";
            btn.disabled = true;
            
            const data = {
                duration: document.getElementById('duration').value,
                src_bytes: document.getElementById('src_bytes').value,
                dst_bytes: document.getElementById('dst_bytes').value,
                count: document.getElementById('count').value,
                srv_count: document.getElementById('srv_count').value
            };

            try {
                const response = await fetch('/predict_manual', {
                    method: 'POST', headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify(data)
                });
                const result = await response.json();
                const resultBox = document.getElementById('manualResult');
                resultBox.style.display = "block";
                
                if (result.status === 'success') {
                    const r = result.data;
                    const colorClass = r.result === "Attack" ? "color: var(--danger)" : "color: var(--success)";
                    resultBox.innerHTML = `
                        <h4 style="${colorClass}; margin-top: 0;">Prediction: ${r.result}</h4>
                        <p style="margin: 5px 0;"><b>Confidence:</b> ${r.confidence}%</p>
                        <p style="margin: 5px 0;"><b>Severity:</b> ${r.severity}</p>
                        <p style="margin: 5px 0;"><b>Type:</b> ${r.attack_type}</p>
                        <hr style="border: 0; border-top: 1px solid var(--border); margin: 10px 0;">
                        <p style="margin: 5px 0; font-size: 0.9rem;"><b>XAI Analysis:</b> ${r.reason}</p>
                    `;
                } else {
                    resultBox.innerHTML = `<span style="color: var(--danger)">Error: ${result.message}</span>`;
                }
            } catch (error) {
                console.error("Manual Scan Error:", error);
            } finally {
                btn.textContent = originalText;
                btn.disabled = false;
            }
        });
    }

    // --- 5. Batch CSV Upload ---
    const uploadForm = document.getElementById('uploadForm');
    if (uploadForm) {
        uploadForm.addEventListener('submit', async (e) => {
            e.preventDefault();
            const btn = document.getElementById('btnUpload');
            const btnText = document.getElementById('uploadText');
            const spinner = document.getElementById('uploadSpinner');
            
            btn.disabled = true;
            btnText.textContent = "Processing... ";
            spinner.style.display = "inline-block";

            const fileInput = document.getElementById('csvFile');
            const formData = new FormData();
            formData.append('file', fileInput.files[0]);

            try {
                const response = await fetch('/predict_file', { method: 'POST', body: formData });
                const result = await response.json();
                const resultBox = document.getElementById('uploadResult');
                resultBox.style.display = "block";

                if (result.status === 'success') {
                    resultBox.innerHTML = `
                        <span style="color: var(--success); font-weight: bold;">${result.message}</span><br>
                        <a href='/dashboard' class='btn btn-primary' style='display: inline-block; margin-top: 15px;'>View Analytics Dashboard</a>
                    `;
                } else {
                    resultBox.innerHTML = `<span style="color: var(--danger); font-weight: bold;">Error: ${result.message}</span>`;
                }
            } catch (error) {
                console.error("Batch Upload Error:", error);
            } finally {
                btn.disabled = false;
                btnText.textContent = "Process Batch File";
                spinner.style.display = "none";
                fileInput.value = ""; 
            }
        });
    }
});