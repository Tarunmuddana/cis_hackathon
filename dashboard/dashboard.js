document.addEventListener('DOMContentLoaded', () => {

    // Chart instances
    let severityChart, typeChart, ipChart;

    // Default Chart styling options for dark theme
    Chart.defaults.color = '#94a3b8';
    Chart.defaults.borderColor = 'rgba(51, 65, 85, 0.5)';

    function initCharts() {
        const sevCtx = document.getElementById('severityChart').getContext('2d');
        severityChart = new Chart(sevCtx, {
            type: 'doughnut',
            data: {
                labels: ['Low', 'Medium', 'High'],
                datasets: [{
                    data: [0, 0, 0],
                    backgroundColor: ['#10b981', '#f59e0b', '#ef4444'],
                    borderWidth: 0
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                plugins: { legend: { position: 'bottom' } },
                cutout: '70%'
            }
        });

        const typeCtx = document.getElementById('typeChart').getContext('2d');
        typeChart = new Chart(typeCtx, {
            type: 'bar',
            data: {
                labels: [],
                datasets: [{
                    label: 'Count',
                    data: [],
                    backgroundColor: '#3b82f6',
                    borderRadius: 4
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                plugins: { legend: { display: false } },
                scales: {
                    y: { beginAtZero: true, suggestedMax: 5 }
                }
            }
        });

        const ipCtx = document.getElementById('ipChart').getContext('2d');
        ipChart = new Chart(ipCtx, {
            type: 'bar',
            data: {
                labels: [],
                datasets: [{
                    label: '# of Attacks',
                    data: [],
                    backgroundColor: '#8b5cf6',
                    borderRadius: 4
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                indexAxis: 'y', // horizontal bar chart
                plugins: { legend: { display: false } },
                scales: {
                    x: { beginAtZero: true }
                }
            }
        });
    }

    async function updateDashboard() {
        try {
            const response = await fetch('/api/stats');
            const data = await response.json();

            // Format UI Text
            document.getElementById('totalAttacks').innerText = data.total_attacks;
            document.getElementById('bannedCount').innerText = data.banned_ips_count;

            // Update Severity Chart
            severityChart.data.datasets[0].data = [
                data.severity['LOW'] || 0,
                data.severity['MEDIUM'] || 0,
                data.severity['HIGH'] || 0
            ];
            severityChart.update();

            // Update Attack Type Chart
            typeChart.data.labels = Object.keys(data.attack_types);
            typeChart.data.datasets[0].data = Object.values(data.attack_types);
            typeChart.update();

            // Update IP Chart
            let ipLabels = [];
            let ipData = [];
            data.top_ips.forEach(entry => {
                ipLabels.push(entry[0]);
                ipData.push(entry[1]);
            });
            ipChart.data.labels = ipLabels;
            ipChart.data.datasets[0].data = ipData;
            ipChart.update();

            // Update Ban Management Table
            const banContainer = document.getElementById('banManagementContent');
            if (!data.banned_ips || data.banned_ips.length === 0) {
                banContainer.innerHTML = '<p style="color: var(--text-secondary); font-size: 0.9rem;">No IPs currently banned.</p>';
            } else {
                let html = `
                    <table style="width: 100%; border-collapse: collapse; text-align: left; font-size: 0.95rem;">
                        <tr style="border-bottom: 1px solid var(--card-border);">
                            <th style="padding: 12px; color: var(--text-secondary);">IP Address</th>
                            <th style="padding: 12px; text-align: right; color: var(--text-secondary);">Action</th>
                        </tr>
                `;
                data.banned_ips.forEach(ip => {
                    html += `
                        <tr style="border-bottom: 1px solid rgba(51, 65, 85, 0.5);">
                            <td style="padding: 12px;">${escapeHtml(ip)}</td>
                            <td style="padding: 12px; text-align: right;">
                                <button onclick="unbanIp('${escapeHtml(ip)}')" style="background: var(--accent-green); color: #fff; border: none; padding: 6px 14px; border-radius: 6px; cursor: pointer; font-weight: 600; font-family: inherit; font-size: 0.85rem; transition: opacity 0.2s;">
                                    Unban IP
                                </button>
                            </td>
                        </tr>
                    `;
                });
                html += '</table>';
                banContainer.innerHTML = html;
            }

        } catch (error) {
            console.error("Dashboard failed to fetch stats", error);
        }
    }

    // Utility for safely rendering IPs
    function escapeHtml(unsafe) {
        return (unsafe || '').toString()
             .replace(/&/g, "&amp;")
             .replace(/</g, "&lt;")
             .replace(/>/g, "&gt;")
             .replace(/"/g, "&quot;")
             .replace(/'/g, "&#039;");
    }

    // Global Unban function
    window.unbanIp = async function(ip) {
        if (!confirm(`Are you sure you want to unban IP: ${ip}?`)) return;
        
        try {
            const res = await fetch('/api/unban', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ ip: ip })
            });
            
            if (res.ok) {
                // Immediately refresh table
                updateDashboard();
            } else {
                const data = await res.json();
                alert(`Error: ${data.error || 'Failed to unban IP'}`);
            }
        } catch (e) {
            console.error(e);
            alert("Network error unbanning IP.");
        }
    };

    // Initialize and loop
    initCharts();
    updateDashboard();
    
    // Auto refresh every 5 seconds
    setInterval(updateDashboard, 5000);
});
