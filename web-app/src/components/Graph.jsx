import React from 'react';
import { Line, Bar, Pie } from 'react-chartjs-2';
import { Chart as ChartJS, CategoryScale, LinearScale, BarElement, Title, Tooltip, Legend, ArcElement, LineElement, PointElement, Filler } from 'chart.js';
import '../styles/Graph.css';

// Register Chart.js components
ChartJS.register(
  CategoryScale,
  LinearScale,
  BarElement,
  ArcElement,
  Title,
  Tooltip,
  Legend,
  LineElement,
  PointElement,
  Filler
);

const DashboardCharts = ({ fileData = [], vulnerabilityData = [] }) => {
  const fileTypeData = fileData.reduce((acc, file) => {
    acc[file.type] = (acc[file.type] || 0) + 1;
    return acc;
  }, {});

  const fileSizeData = fileData.map(file => ({
    name: file.file || 'Unknown',
    size: parseFloat(file.size.replace('MB', '')) || 0
  }));

  const vulnerabilityCountData = fileData.reduce((acc, file) => {
    const range = file.vulnerability < 1 ? '0' : 
      file.vulnerability <= 50 ? '1-50' : 
      file.vulnerability <= 100 ? '51-100' : '100+';
    acc[range] = (acc[range] || 0) + 1;
    return acc;
  }, {});

  const vulnerabilityTypeData = vulnerabilityData.reduce((acc, data) => {
    acc[data.type] = (acc[data.type] || 0) + 1;
    return acc;
  }, {});

  return (
    <div className="dashboard-charts-container">
              <h1 className="charts__title">Graphs</h1>
              <hr className="charts__separator" />
      {/* File Type Line Chart */}
      <div className="chart-container line-chart-container">
        <h2>File Type Distribution</h2>
        <Line
          data={{
            labels: Object.keys(fileTypeData),
            datasets: [{
              label: 'Number of Files',
              data: Object.values(fileTypeData),
              borderColor: 'rgba(75, 192, 192, 1)',
              backgroundColor: 'rgba(75, 192, 192, 0.2)',
              fill: true,
            }],
          }}
          options={{
            responsive: true,
            plugins: {
              legend: { display: true },
              tooltip: { callbacks: { label: (tooltipItem) => `Files: ${tooltipItem.raw}` } },
            },
            scales: {
              x: { title: { display: true, text: 'File Type' } },
              y: { 
                title: { display: true, text: 'Number of Files' },
                beginAtZero: true  // Ensure the y-axis starts at zero
              }
            }
          }}
        />
      </div>

      {/* File Size Bar Chart */}
      <div className="chart-container bar-chart-container">
        <h2>File Size Distribution</h2>
        <Bar
          data={{
            labels: fileSizeData.map(data => data.name),
            datasets: [{
              label: 'File Size (MB)',
              data: fileSizeData.map(data => data.size),
              backgroundColor: 'rgba(153, 102, 255, 0.5)',
              borderColor: 'rgba(153, 102, 255, 1)',
              borderWidth: 1,
            }],
          }}
          options={{
            responsive: true,
            plugins: {
              legend: { display: true },
              tooltip: { callbacks: { label: (tooltipItem) => `${tooltipItem.label}: ${tooltipItem.raw} MB` } },
            },
            scales: {
              x: { title: { display: true, text: 'File Name' } },
              y: { title: { display: true, text: 'Size (MB)' } }
            }
          }}
        />
      </div>

      {/* Vulnerability Count Histogram */}
      <div className="chart-container bar-chart-container">
        <h2>Vulnerability Count Distribution</h2>
        <Bar
          data={{
            labels: Object.keys(vulnerabilityCountData),
            datasets: [{
              label: 'Number of Files',
              data: Object.values(vulnerabilityCountData),
              backgroundColor: 'rgba(255, 159, 64, 0.5)',
              borderColor: 'rgba(255, 159, 64, 1)',
              borderWidth: 1,
            }],
          }}
          options={{
            responsive: true,
            plugins: {
              legend: { display: true },
              tooltip: { callbacks: { label: (tooltipItem) => `Files: ${tooltipItem.raw}` } },
            },
            scales: {
              x: { title: { display: true, text: 'Vulnerability Count Range' } },
              y: { title: { display: true, text: 'Number of Files' } }
            }
          }}
        />
      </div>

      {/* Vulnerability Type Pie Chart */}
      <div className="chart-container pie-chart-container">
        <h2>Vulnerability Type Distribution</h2>
        <Pie
          data={{
            labels: Object.keys(vulnerabilityTypeData),
            datasets: [{
              data: Object.values(vulnerabilityTypeData),
              backgroundColor: ['rgba(255, 99, 132, 0.5)', 'rgba(54, 162, 235, 0.5)', 'rgba(255, 206, 86, 0.5)', 'rgba(75, 192, 192, 0.5)'],
              borderColor: ['rgba(255, 99, 132, 1)', 'rgba(54, 162, 235, 1)', 'rgba(255, 206, 86, 1)', 'rgba(75, 192, 192, 1)'],
              borderWidth: 1,
            }],
          }}
          options={{
            responsive: true,
            plugins: {
              legend: { position: 'top' },
              tooltip: { callbacks: { label: (tooltipItem) => `${tooltipItem.label}: ${tooltipItem.raw}` } },
            }
          }}
        />
      </div>
    </div>
  );
};

export default DashboardCharts;
