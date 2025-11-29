// charts.js - for rendering graphs on admin dashboard

// Fuel Level Chart
const fuelCtx = document.getElementById('fuelChart');
if (fuelCtx) {
    // Data is passed from the template via data-* attributes
    const fuelLabels = JSON.parse(fuelCtx.dataset.labels);
    const fuelData = JSON.parse(fuelCtx.dataset.data);

    new Chart(fuelCtx, {
        type: 'bar',
        data: {
            labels: fuelLabels,
            datasets: [{
                label: 'Fuel Level (%)',
                data: fuelData,
                backgroundColor: 'rgba(255, 159, 64, 0.6)',
                borderColor: 'rgba(255, 159, 64, 1)',
                borderWidth: 1
            }]
        },
        options: {
            scales: {
                y: {
                    beginAtZero: true,
                    max: 100
                }
            },
            responsive: true,
            maintainAspectRatio: false
        }
    });
}


// Attendance Chart
const attendanceCtx = document.getElementById('attendanceChart');
if (attendanceCtx) {
    const attendanceLabels = JSON.parse(attendanceCtx.dataset.labels);
    const attendanceData = JSON.parse(attendanceCtx.dataset.data);

    new Chart(attendanceCtx, {
        type: 'line',
        data: {
            labels: attendanceLabels,
            datasets: [{
                label: 'Daily Check-ins',
                data: attendanceData,
                fill: true,
                backgroundColor: 'rgba(54, 162, 235, 0.2)',
                borderColor: 'rgba(54, 162, 235, 1)',
                tension: 0.1
            }]
        },
        options: {
            scales: {
                y: {
                    beginAtZero: true
                }
            },
            responsive: true,
            maintainAspectRatio: false
        }
    });
}