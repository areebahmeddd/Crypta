// src/components/Dashboard.js
import React, { useState, useCallback, useEffect} from 'react';
import Modal from 'react-modal';
import ModalPage from '../pages/Modal'
import { useLocation } from 'react-router-dom';
import jsPDF from 'jspdf';
import * as XLSX from 'xlsx';
import { saveAs } from 'file-saver';
import '../styles/Dashboard.css';
import 'jspdf-autotable';  // Import the autoTable plugin
import { FontAwesomeIcon } from '@fortawesome/react-fontawesome';
import { faCaretDown, faSearch, faTimes, faChevronLeft, faChevronRight, faFilter, faArrowDown, faShareSquare, faSortUp, faSortDown} from '@fortawesome/free-solid-svg-icons';
import _ from 'lodash';
import { Line, Bar } from 'react-chartjs-2';
import { Chart as ChartJS, CategoryScale, LinearScale, PointElement, LineElement, BarElement, Title, Tooltip, Legend } from 'chart.js';

ChartJS.register(
  CategoryScale,
  LinearScale,
  PointElement,
  LineElement,
  BarElement,
  Title,
  Tooltip,
  Legend
);

Modal.setAppElement('#root'); // For accessibility

const Dashboard = () => {
  const [selectedData, setSelectedData] = useState(null);
  const [isModalOpen, setIsModalOpen] = useState(false);
  const [isOpen, setIsOpen] = useState(false);
  const [selectedFormat, setSelectedFormat] = useState('PDF');
  const [filteredFileData, setFilteredFileData] = useState([]);
  const [filteredVulnerabilityData, setFilteredVulnerabilityData] = useState([]);
  const [searchTerm, setSearchTerm] = useState('');
  const [showAllAlerts, setShowAllAlerts] = useState(false);
  const [filePage, setFilePage] = useState(1); // Page for file details table
  const [vulnPage, setVulnPage] = useState(1); // Page for vulnerability table
  const [isExportMenuOpen, setIsExportMenuOpen] = useState(false);
  const [selectedExportFormat, setSelectedExportFormat] = useState('JSON');
  const [sortCriteria, setSortCriteria] = useState({ key: 'size', order: 'asc' });
  const [displayedFileData, setDisplayedFileData] = useState([]);

  const location = useLocation();
  const {
    processedData = [],
    rulesFile,
    filesFromHome = [], // Add filesFromHome here
  } = location.state || {};

  const rowsPerPage = 5;

    // Use mock data
    const fileData = [
      { file: 'report1.pdf', type: 'PDF', size: '1.2 MB', vulnerability: 15 },
      { file: 'data2.csv', type: 'CSV', size: '800 KB', vulnerability: 0 },
      { file: 'image3.png', type: 'PNG', size: '1.5 MB', vulnerability: 63 },
      { file: 'document4.docx', type: 'DOCX', size: '500 KB', vulnerability: 11 },
      { file: 'archive5.zip', type: 'ZIP', size: '3.0 MB', vulnerability: 7 },
      { file: 'data2.csv', type: 'CSV', size: '800 KB', vulnerability: 2 },
      { file: 'image3.png', type: 'PNG', size: '1.5 MB', vulnerability: 3 },
      { file: 'document4.docx', type: 'DOCX', size: '500 KB', vulnerability: 32 },
      { file: 'archive5.zip', type: 'ZIP', size: '3.0 MB', vulnerability: 47 },
    ];

    const vulnerabilityData = [
      {
        file: "malware.exe",
        type: "Malware",
        indicators: [
          { level: "High", type: "File Hash", indicator: "abc123hash" },
          { level: "Medium", type: "IP Address", indicator: "192.168.1.1" },
          { level: "Low", type: "Domain", indicator: "malicious.com" }
        ]
      },
      {
        file: "phishing.docx",
        type: "Phishing Document",
        indicators: [
          { level: "High", type: "File Hash", indicator: "def456hash" },
          { level: "Low", type: "Email Address", indicator: "phish@malicious.com" },
          { level: "Medium", type: "URL", indicator: "malicious-link.com" }
        ]
      },
      {
        file: "ransomware.zip",
        type: "Ransomware",
        indicators: [
          { level: "Medium-High", type: "File Hash", indicator: "ransom123hash" },
          { level: "High", type: "IP Address", indicator: "203.0.113.42" },
          { level: "Low", type: "Domain", indicator: "ransom-domain.com" }
        ]
      },
      { file: 'archive5.zip', type: 'Ransomware', indicators: [{ level: 'High', type: 'Encryption', indicator: 'ransomware-encryptor.exe' }] },
      { file: 'image3.png', type: 'Malware', indicators: [{ level: 'Medium', type: 'Virus', indicator: 'malicious_code.exe' }] },
      { file: 'document4.docx', type: 'Phishing', indicators: [{ level: 'Low', type: 'Email', indicator: 'phishing@example.com' }] },
      { file: 'data2.csv', type: 'Cross-Site Scripting', indicators: [{ level: 'Medium', type: 'XSS', indicator: '<script>alert(1)</script>' }] },
      { file: 'image3.png', type: 'Malware', indicators: [{ level: 'Low', type: 'Virus', indicator: 'malicious_code.exe' }] },

    ];

    const [alerts, setAlerts] = useState([
      { id: 1, message: "Critical system update required. Please update your software to ensure security." },
      { id: 2, message: "Unauthorized access attempt detected. Review your security settings immediately." },
      { id: 3, message: "New vulnerability discovered in your application. Apply the latest patch to address the issue." },
      { id: 4, message: "Backup failure detected. Ensure your backup system is functioning properly to avoid data loss." },
      { id: 5, message: "High CPU usage alert. Check for any processes that might be consuming excessive resources." },
      // More alerts...
    ]);

    const options = {
      responsive: true,
      maintainAspectRatio: false,
      plugins: {
        legend: {
          position: 'top',
          labels: {
            color: '#333', // Darker color for better readability
            font: {
              size: 14, // Increase font size
            },
          },
        },
        tooltip: {
          backgroundColor: '#333', // Dark tooltip background
          titleColor: '#fff', // White tooltip title
          bodyColor: '#fff', // White tooltip body
          borderColor: '#ddd', // Light border color
          borderWidth: 1, // Border width for tooltip
        },
      },
      scales: {
        x: {
          grid: {
            borderColor: '#ddd', // Light grid line color
          },
          ticks: {
            color: '#333', // Darker color for axis ticks
          },
        },
        y: {
          grid: {
            borderColor: '#ddd', // Light grid line color
          },
          ticks: {
            color: '#333', // Darker color for axis ticks
          },
        },
      },
    };
    

  // Extract file data and vulnerabilities from processedData
  // const fileData = processedData.map((data) => ({
  //   file: data.fileName,
  //   type: data.fileType,
  //   size: data.fileSize,
  //   vulnerability: data.vulnerabilityCount, // Assuming vulnerabilityCount is part of processedData
  // }));

  // const vulnerabilityData = processedData.map((data) => ({
  //   file: data.fileName,
  //   type: data.vulnerabilityType, // Assuming vulnerabilityType is part of processedData
  //   indicators: data.indicatorsOfCompromise || [], // Assuming indicatorsOfCompromise is an array in processedData
  // }));


  // Prepare data for charts
  const fileTypes = fileData.reduce((acc, data) => {
    acc[data.type] = (acc[data.type] || 0) + 1;
    return acc;
  }, {});

  const vulnerabilities = vulnerabilityData.reduce((acc, data) => {
    acc[data.type] = (acc[data.type] || 0) + 1;
    return acc;
  }, {});

  const fileTypeData = {
    labels: Object.keys(fileTypes),
    datasets: [
      {
        label: 'File Types',
        data: Object.values(fileTypes),
        backgroundColor: 'rgba(75, 192, 192, 0.2)',
        borderColor: 'rgba(75, 192, 192, 1)',
        borderWidth: 1,
      },
    ],
  };

  const vulnerabilityDataSet = {
    labels: Object.keys(vulnerabilities),
    datasets: [
      {
        label: 'Vulnerabilities',
        data: Object.values(vulnerabilities),
        backgroundColor: 'rgba(153, 102, 255, 0.2)',
        borderColor: 'rgba(153, 102, 255, 1)',
        borderWidth: 1,
      },
    ],
  };

  const handleSearch = useCallback(() => {
    const searchTermLower = searchTerm.toLowerCase();

    const filteredFiles = fileData.filter(data =>
      data.file.toLowerCase().includes(searchTermLower) ||
      data.type.toLowerCase().includes(searchTermLower)
    );

    const filteredVulnerabilities = vulnerabilityData.filter(data =>
      data.file.toLowerCase().includes(searchTermLower) ||
      data.type.toLowerCase().includes(searchTermLower)
    );

    setFilteredFileData(filteredFiles);
    setFilteredVulnerabilityData(filteredVulnerabilities);
  }, [searchTerm]);

  const debouncedSearch = useCallback(
    _.debounce(() => {
      handleSearch();
    }, 300),
    [handleSearch]
  );

  useEffect(() => {
    debouncedSearch();
  }, [searchTerm, debouncedSearch]);

  const handleSearchChange = (e) => {
    setSearchTerm(e.target.value);
  };

  const handleSort = (key) => {
    const newOrder = (sortCriteria.key === key && sortCriteria.order === 'asc') ? 'desc' : 'asc';
    setSortCriteria({ key, order: newOrder });
  };  
  
  const convertSizeToBytes = (sizeStr) => {
    const units = ['B', 'KB', 'MB', 'GB', 'TB'];
    const [size, unit] = sizeStr.split(/([a-zA-Z]+)/); // Split number and unit
  
    const unitIndex = units.indexOf(unit.toUpperCase());
    if (unitIndex === -1) return parseFloat(size); // Fallback in case of an unknown unit
  
    return parseFloat(size) * Math.pow(1024, unitIndex); // Convert to bytes
  };
  
  useEffect(() => {
    const sortedData = [...fileData].sort((a, b) => {
      const aValue = a[sortCriteria.key];
      const bValue = b[sortCriteria.key];
  
      // Special case for sorting file sizes
      if (sortCriteria.key === 'size') {
        const aBytes = convertSizeToBytes(aValue);
        const bBytes = convertSizeToBytes(bValue);
        return sortCriteria.order === 'asc' ? aBytes - bBytes : bBytes - aBytes;
      }
  
      // Sorting vulnerability counts or other numerical fields
      if (sortCriteria.key === 'vulnerability') {
        return sortCriteria.order === 'asc' ? aValue - bValue : bValue - aValue;
      }
  
      // Sorting other string fields
      if (aValue < bValue) return sortCriteria.order === 'asc' ? -1 : 1;
      if (aValue > bValue) return sortCriteria.order === 'asc' ? 1 : -1;
      return 0;
    });
  
    const startIndex = (filePage - 1) * rowsPerPage;
    const endIndex = filePage * rowsPerPage;
    setDisplayedFileData(sortedData.slice(startIndex, endIndex));
  }, [fileData, filePage, rowsPerPage, sortCriteria]);
  
// Logic for File Pagination (max two numbers shown)
const totalFilePages = Math.ceil(fileData.length / rowsPerPage);
const totalVulnPages = Math.ceil(vulnerabilityData.length / rowsPerPage);

const maxPageNumbersToShow = 2;
const startFilePage = Math.max(1, filePage - 1);  // Show the current page and the previous one
const endFilePage = Math.min(totalFilePages, filePage + 1);  // Show the current page and the next one

const handleFilePageChange = (directionOrPage) => {
  if (typeof directionOrPage === 'number') {
    setFilePage(directionOrPage);
  } else {
    if (directionOrPage === 'next' && filePage < totalFilePages) {
      setFilePage(filePage + 1);
    } else if (directionOrPage === 'prev' && filePage > 1) {
      setFilePage(filePage - 1);
    }
  }
};

  // Logic for Vulnerability Pagination (max two numbers shown)
const startVulnPage = Math.max(1, vulnPage - 1);  // Show the current page and the previous one
const endVulnPage = Math.min(totalVulnPages, vulnPage + 1);  // Show the current page and the next one

const handleVulnPageChange = (directionOrPage) => {
  if (typeof directionOrPage === 'number') {
    setVulnPage(directionOrPage);
  } else {
    if (directionOrPage === 'next' && vulnPage < totalVulnPages) {
      setVulnPage(vulnPage + 1);
    } else if (directionOrPage === 'prev' && vulnPage > 1) {
      setVulnPage(vulnPage - 1);
    }
  }
};

  //     // Get sliced data for the current page (File Details)
  // const displayedFileData = fileData.slice((filePage - 1) * rowsPerPage, filePage * rowsPerPage);

  // Get sliced data for the current page (Vulnerability Information)
  const displayedVulnerabilityData = vulnerabilityData.slice((vulnPage - 1) * rowsPerPage, vulnPage * rowsPerPage);

  const getVulnerabilityColor = (count) => {
    if (count > 40) return '#FF0000';
    if (count >= 30) return '#FF6F00'; 
    if (count >= 21) return '#FFEB3B'; 
    if (count >= 16) return '#FFC107'; 
    if (count >= 11) return '#FF9800'; 
    if (count >= 6) return '#FF5722'; 
    if (count >= 1) return '#FF8C00'; 
    return '#4CAF50'; 
  };
  

  const handleViewClick = (data) => {
    setSelectedData(data);
    setIsModalOpen(true);
  };

  const handleCloseModal = () => {
    setIsModalOpen(false);
    setSelectedData(null);
  };

  const toggleMenu = () => {
    setIsOpen(!isOpen);
  };

  const selectFormat = (format) => {
    setSelectedFormat(format);
    setIsOpen(false);
  };

   // Generate PDF report
   const downloadPDF = () => {
    const doc = new jsPDF();
    doc.text('File Details Report', 20, 10);
    doc.autoTable({
      head: [['File', 'Type', 'Size', 'Vulnerability']],
      body: fileData.map(({ file, type, size, vulnerability }) => [file, type, size, vulnerability]),
    });
    doc.text('Vulnerability Information', 20, 40);
    doc.autoTable({
      head: [['File', 'Vulnerability Type', 'Indicators']],
      body: vulnerabilityData.map(({ file, type }) => [file, type]),
    });
    doc.save('report.pdf');
  };

  // Generate Excel report
  const downloadXLSX = () => {
    const wb = XLSX.utils.book_new();
    const fileSheet = XLSX.utils.json_to_sheet(fileData);
    const vulnerabilitySheet = XLSX.utils.json_to_sheet(vulnerabilityData);
    XLSX.utils.book_append_sheet(wb, fileSheet, 'File Details');
    XLSX.utils.book_append_sheet(wb, vulnerabilitySheet, 'Vulnerability Details');
    const wbout = XLSX.write(wb, { bookType: 'xlsx', type: 'array' });
    saveAs(new Blob([wbout], { type: 'application/octet-stream' }), 'report.xlsx');
  };

  // Generate CSV report
  const downloadCSV = () => {
    const csvContent = [
      ['File', 'Type', 'Size', 'Vulnerability'],
      ...fileData.map(({ file, type, size, vulnerability }) => [file, type, size, vulnerability])
    ]
      .map((row) => row.join(','))
      .join('\n');
    const blob = new Blob([csvContent], { type: 'text/csv;charset=utf-8;' });
    saveAs(blob, 'report.csv');
  };

  const handleDownload = () => {
    switch (selectedFormat) {
      case 'PDF':
        downloadPDF();
        break;
      case 'XLSX':
        downloadXLSX();
        break;
      case 'CSV':
        downloadCSV();
        break;
      default:
        break;
    }
  };

  // Toggle the export dropdown menu
  const toggleExportMenu = () => {
    setIsExportMenuOpen((prev) => !prev);
  };

  // Handle export format selection
  const selectExportFormat = (format) => {
    setSelectedExportFormat(format);
    setIsExportMenuOpen(false); // Close the dropdown after selecting a format
  };

  // Handle export action
  const handleExport = () => {
    // Your export logic here, e.g., sending the selected format to the backend
    console.log(`Exporting in ${selectedExportFormat} format`);
  };

  return (
    <div className="dashboard__container">

<h1 className="dashboard__title">Dashboard</h1>
<hr className="dashboard__separator" />

<div className="dashboard__search-bar-container rounded-floating">
  <div className="dashboard__search-bar-wrapper">
    <FontAwesomeIcon icon={faSearch} size="lg" className="dashboard__search-icon floating-icon" />
    <input
      type="text"
      className="dashboard__search-bar floating"
      placeholder="Search files..."
      onChange={handleSearchChange}
      value={searchTerm}
    />
    <button className="dashboard__search-filter right-aligned">
    {searchTerm && (
      <button className="dashboard__search-clear" onClick={() => setSearchTerm('')}>
        <FontAwesomeIcon icon={faTimes} size="lg" />
      </button>
    )}
      <FontAwesomeIcon icon={faFilter} size="lg"/>
    </button>
  </div>
</div>


{/* File Details Card */}
<h2>File Details</h2>
<div className="dashboard__card">
  <div className="dashboard__card-header">
    <div>File</div>
    <div>Type</div>
    <div>
  Size
  <button className="sort-button-custom" onClick={() => handleSort('size')}>
    {sortCriteria.key === 'size' && sortCriteria.order === 'asc' ? (
      <FontAwesomeIcon icon={faSortUp} />
    ) : (
      <FontAwesomeIcon icon={faSortDown} />
    )}
  </button>
</div>
<div>
  Vulnerability Count
  <button className="sort-button-custom" onClick={() => handleSort('vulnerability')}>
    {sortCriteria.key === 'vulnerability' && sortCriteria.order === 'asc' ? (
      <FontAwesomeIcon icon={faSortUp} />
    ) : (
      <FontAwesomeIcon icon={faSortDown} />
    )}
  </button>
</div>
  </div>
  
  <div className="dashboard__card-body">
    {displayedFileData.map((data, index) => (
      <div key={index} className="dashboard__card-row">
        <div>{data.file}</div>
        <div>{data.type}</div>
        <div>{data.size}</div>
        <div><div className="vul_count" 
          style={{
            backgroundColor: getVulnerabilityColor(data.vulnerability), // Background color based on the vulnerability count
            padding: '5px 0', // Adjust padding as needed
            borderRadius: '5px', // Optional: for rounded corners
            display: 'inline-block' // Makes the div fit the content size
          }}>
  {data.vulnerability}
</div>
</div>
      </div>
    ))}
  </div>

   {/* Total Files */}
   <div className="total-files">
    Total Files: {fileData.length}
  </div>

  {/* Pagination Controls */}
  <div className="pagination-controls">
    <button 
      className="pagination-btn" 
      onClick={() => handleFilePageChange('prev')} 
      disabled={filePage === 1}
    >
      <FontAwesomeIcon icon={faChevronLeft} />
    </button>

    {Array.from({ length: endFilePage - startFilePage + 1 }, (_, i) => {
      const pageNumber = startFilePage + i;
      return (
        <button
          key={pageNumber}
          className={`pagination-number ${filePage === pageNumber ? 'active' : ''}`}
          onClick={() => handleFilePageChange(pageNumber)}
        >
          {pageNumber}
        </button>
      );
    })}

    <button 
      className="pagination-btn" 
      onClick={() => handleFilePageChange('next')} 
      disabled={filePage === totalFilePages}
    >
      <FontAwesomeIcon icon={faChevronRight} />
    </button>
  </div>
</div>

{/* Vulnerability Information Card */}
<h2>Vulnerability Information</h2>
<div className="dashboard_v_card">
  <div className="dashboard_v_card-header">
    <div>File</div>
    <div>Vulnerability Type</div>
    <div>Indicators of Compromise</div>
  </div>
  <div className="dashboard_v_card-body">
    {displayedVulnerabilityData.map((data, index) => (
      <div key={index} className="dashboard_v_card-row">
        <div>{data.file}</div>
        <div>{data.type}</div>
        <div>
          <button className="dashboard__view-btn" onClick={() => handleViewClick(data)}>
            View
          </button>
        </div>
      </div>
    ))}
  </div>

     {/* Total Files */}
     <div className="total-v-files">
    Total Files: {vulnerabilityData.length}
  </div>

  {/* Pagination Controls */}
  <div className="pagination-controls">
    <button 
      className="pagination-btn" 
      onClick={() => handleVulnPageChange('prev')} 
      disabled={vulnPage === 1}
    >
      <FontAwesomeIcon icon={faChevronLeft} />
    </button>

    {Array.from({ length: endVulnPage - startVulnPage + 1 }, (_, i) => {
      const pageNumber = startVulnPage + i;
      return (
        <button
          key={pageNumber}
          className={`pagination-number ${vulnPage === pageNumber ? 'active' : ''}`}
          onClick={() => handleVulnPageChange(pageNumber)}
        >
          {pageNumber}
        </button>
      );
    })}

    <button 
      className="pagination-btn" 
      onClick={() => handleVulnPageChange('next')} 
      disabled={vulnPage === totalVulnPages}
    >
      <FontAwesomeIcon icon={faChevronRight} />
    </button>
  </div>
</div> 

    {/* Modal */}
    <ModalPage isOpen={isModalOpen} onClose={handleCloseModal} data={selectedData} />

      <div className="dashboard__alert-section">
  <h2 className="dashboard__alert-title">Alerts</h2>
  <hr className="dashboard__alert-separator" />
  <ul className="dashboard__alert-list">
    {alerts.slice(0, showAllAlerts ? alerts.length : 3).map(alert => (
      <li key={alert.id} className="dashboard__alert-item">
        {alert.message}
      </li>
    ))}
  </ul>
  {alerts.length > 3 && (
    <button className="dashboard__show-more" onClick={() => setShowAllAlerts(!showAllAlerts)}>
      {showAllAlerts ? "Show Less" : "Show More"}
    </button>
  )}
</div>

<div className="dashboard__buttons-container">
{/* Download Button Section */}
<div className="dashboard__download-section">
  <button className="dashboard__download-btn" onClick={handleDownload}>
    Download Report <FontAwesomeIcon icon={faArrowDown} className="dashboard__download-icon" />
  </button>

  {/* Download Dropdown */}
  <div className="dashboard__dropdown">
    <button onClick={toggleMenu} className="dashboard__dropdown-toggle">
      {selectedFormat} <FontAwesomeIcon icon={faCaretDown} className="dashboard__dropdown-icon" />
    </button>
    {isOpen && (
      <div className="dashboard__dropdown-menu">
        <div onClick={() => selectFormat('PDF')}>PDF</div>
        <div onClick={() => selectFormat('XLSX')}>XLSX</div>
        <div onClick={() => selectFormat('CSV')}>CSV</div>
      </div>
    )}
  </div>
</div>

{/* Export Button Section */}
<div className="dashboard__export-section">
  <button className="dashboard__export-btn" onClick={handleExport}>
    Export Analysis <FontAwesomeIcon icon={faShareSquare} className="dashboard__export-icon" />
  </button>

  {/* Export Dropdown */}
  <div className="dashboard__dropdown">
    <button onClick={toggleExportMenu} className="dashboard__dropdown-toggle">
      {selectedExportFormat} <FontAwesomeIcon icon={faCaretDown} className="dashboard__dropdown-icon" />
    </button>
    {isExportMenuOpen && (
      <div className="dashboard__dropdown-export-menu">
        <div onClick={() => selectExportFormat('JSON')}>JSON</div>
        <div onClick={() => selectExportFormat('XML')}>XML</div>
        <div onClick={() => selectExportFormat('TEXT')}>TEXT</div>
        <div onClick={() => selectExportFormat('MD')}>MD</div>
      </div>
    )}
  </div>
</div>

</div>

      <h1 className="graph__title">Graphs</h1>
<hr className="dashboard__separator" />
      <div className="dashboard__charts">
  <div className="dashboard__chart-container">
    <h2>File Types Distribution</h2>
    <Bar data={fileTypeData} options={{ responsive: true }} />
  </div>

  <div className="dashboard__chart-container">
    <h2>Vulnerability Types Distribution</h2>
    <Line data={vulnerabilityDataSet} options={{ responsive: true }} />
  </div>
</div>
    </div>
  );
};

export default Dashboard;
