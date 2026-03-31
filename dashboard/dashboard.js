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

        } catch (error) {
            console.error("Dashboard failed to fetch stats", error);
        }
    }

    // Initialize and loop
    initCharts();
    updateDashboard();
    
    // Auto refresh every 5 seconds
    setInterval(updateDashboard, 5000);
});
