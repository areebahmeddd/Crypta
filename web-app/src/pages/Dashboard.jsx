import React, { useState, useCallback, useEffect } from "react";
import { useLocation } from "react-router-dom";
import { FontAwesomeIcon } from "@fortawesome/react-fontawesome";
import {
  faCaretDown,
  faSearch,
  faTimes,
  faChevronLeft,
  faChevronRight,
  faFilter,
  faArrowDown,
  faShareSquare,
  faSortUp,
  faSortDown,
} from "@fortawesome/free-solid-svg-icons";
import Modal from "react-modal";
import ModalPage from "../components/Modal";
import DashboardCharts from "../components/Graph";
import "../styles/Dashboard.css";
import axios from "axios";
import * as XLSX from "xlsx";
import { saveAs } from "file-saver";
import "jspdf-autotable";
import _ from "lodash";

Modal.setAppElement("#root");

const Dashboard = () => {
  const [selectedData, setSelectedData] = useState(null);
  const [isModalOpen, setIsModalOpen] = useState(false);
  const [isOpen, setIsOpen] = useState(false);
  const [selectedFormat, setSelectedFormat] = useState("PDF");
  const [searchTerm, setSearchTerm] = useState("");
  const [showAllAlerts, setShowAllAlerts] = useState(false);
  const [filePage, setFilePage] = useState(1);
  const [vulnPage, setVulnPage] = useState(1);
  const [isExportMenuOpen, setIsExportMenuOpen] = useState(false);
  const [selectedExportFormat, setSelectedExportFormat] = useState("JSON");
  const [sortCriteria, setSortCriteria] = useState({
    key: "size",
    order: "asc",
  });
  const [rowsPerPage, setRowsPerPage] = useState(5);
  const location = useLocation();
  const { filesFromHome, results, gemini } = location.state || {};
  const alerts = gemini?.alerts || [];
  const recommendedFixes = gemini?.recommended_fixes || [];

  // Group alerts by their type
  const groupedAlerts = alerts.reduce((acc, alert) => {
    const { type, detail } = alert;
    if (!acc[type]) {
      acc[type] = [];
    }
    acc[type].push(detail);
    return acc;
  }, {});

  console.log("Dashboard Data:", filesFromHome, results, gemini);

  // Map data by matching filesFromHome with results based on file names
  const fileData = results.map((data) => {
    // Find the matching file in filesFromHome based on the file name
    const matchingFile = filesFromHome.find((file) => file.name === data.file);

    return {
      file: data.file, // File name from results
      type: matchingFile?.type || "Unknown", // File type from filesFromHome
      size: matchingFile?.size
        ? `${matchingFile.size} MB` // Append 'MB' if size is available
        : "Unknown", // Default to 'Unknown' if size is not available
      vulnerability: data.vulnerability_count, // Vulnerability count from results
    };
  });

  const vulnerabilityData = results.map((data) => {
    // Extract indicators from data.yara
    const indicators =
      Object.entries(data.yara).map(([indicator, count]) => ({
        indicator,
        count,
        level: data.risk_level || "Unknown", // Extract level from results or default to 'Unknown'
        type: data.risk_type || "Unknown", // Extract type from results or default to 'Unknown'
      })) || [];

    return {
      file: data.file, // File name from results
      type: data.vulnerability_type, // Vulnerability type from results
      indicators, // Include the updated indicators
    };
  });

  const [displayedFileData, setDisplayedFileData] = useState(fileData);
  const [displayedVulnerabilityData, setDisplayedVulnerabilityData] =
    useState(vulnerabilityData);

  // Helper function to convert sizes to bytes
  const convertSizeToBytes = (sizeString) => {
    if (!sizeString || typeof sizeString !== "string") return 0;

    const units = ["B", "KB", "MB", "GB", "TB"];
    const sizeParts = sizeString.split(" ");
    const sizeValue = parseFloat(sizeParts[0]);
    const sizeUnit = sizeParts[1]?.toUpperCase() || "B"; // Default to bytes if no unit

    if (isNaN(sizeValue)) return 0; // Handle invalid size value

    const unitIndex = units.indexOf(sizeUnit);
    return unitIndex > 0 ? sizeValue * Math.pow(1024, unitIndex) : sizeValue;
  };

  // Sorting function
  const handleSort = (key) => {
    const newOrder =
      sortCriteria.key === key && sortCriteria.order === "asc" ? "desc" : "asc";
    setSortCriteria({ key, order: newOrder });

    const sortedData = [...displayedFileData].sort((a, b) => {
      let aValue = 0;
      let bValue = 0;

      if (key === "size") {
        // Handle file sizes safely
        aValue = a.size ? convertSizeToBytes(a.size) : 0;
        bValue = b.size ? convertSizeToBytes(b.size) : 0;
      } else if (key === "vulnerability") {
        // Handle vulnerability safely
        aValue = a.vulnerability !== undefined ? a.vulnerability : 0;
        bValue = b.vulnerability !== undefined ? b.vulnerability : 0;
      } else if (key === "type") {
        // Sort by file type alphabetically
        aValue = a.type?.toUpperCase() || "";
        bValue = b.type?.toUpperCase() || "";
      }

      if (aValue < bValue) return newOrder === "asc" ? -1 : 1;
      if (aValue > bValue) return newOrder === "asc" ? 1 : -1;
      return 0;
    });

    setDisplayedFileData(sortedData);
  };

  // Logic for File Pagination (max two numbers shown)
  const totalFilePages = Math.ceil(fileData.length / rowsPerPage);

  const startFilePage = Math.max(1, filePage - 1); // Show the current page and the previous one
  const endFilePage = Math.min(totalFilePages, filePage + 1); // Show the current page and the next one

  const handleFilePageChange = (directionOrPage) => {
    if (typeof directionOrPage === "number") {
      setFilePage(directionOrPage);
    } else {
      if (directionOrPage === "next" && filePage < totalFilePages) {
        setFilePage(filePage + 1);
      } else if (directionOrPage === "prev" && filePage > 1) {
        setFilePage(filePage - 1);
      }
    }
  };

  const totalVulnPages = Math.ceil(vulnerabilityData.length / rowsPerPage);
  // Logic for Vulnerability Pagination (max two numbers shown)
  const startVulnPage = Math.max(1, vulnPage - 1); // Show the current page and the previous one
  const endVulnPage = Math.min(totalVulnPages, vulnPage + 1); // Show the current page and the next one

  const handleVulnPageChange = (directionOrPage) => {
    if (typeof directionOrPage === "number") {
      setVulnPage(directionOrPage);
    } else {
      if (directionOrPage === "next" && vulnPage < totalVulnPages) {
        setVulnPage(vulnPage + 1);
      } else if (directionOrPage === "prev" && vulnPage > 1) {
        setVulnPage(vulnPage - 1);
      }
    }
  };
  // For File Details table
  const currentFilePageData = displayedFileData.slice(
    (filePage - 1) * rowsPerPage,
    filePage * rowsPerPage
  );

  // For Vulnerability Information table
  const currentVulnerabilityPageData = displayedVulnerabilityData.slice(
    (vulnPage - 1) * rowsPerPage,
    vulnPage * rowsPerPage
  );

  const getVulnerabilityColor = (count) => {
    if (count >= 101) return "#DF5656"; // Dark Red
    if (count >= 51) return "#F8A72C"; // Orange
    if (count >= 1) return "#FFD65A"; // Yellow
    return "#8AC449"; // Green
  };

  const handleSearchChange = (e) => {
    const value = e.target.value.toLowerCase();
    console.log("Search Term: ", value); // Debug to check the search term
    setSearchTerm(value);

    if (value) {
      // Filter File Details based on file name
      const filteredFileData = fileData.filter((file) =>
        file.file.toLowerCase().includes(value)
      );
      console.log("Filtered File Data: ", filteredFileData); // Debug to check filtered results

      // Filter Vulnerability Information based on file name
      const filteredVulnerabilityData = vulnerabilityData.filter((file) =>
        file.file.toLowerCase().includes(value)
      );
      console.log("Filtered Vulnerability Data: ", filteredVulnerabilityData); // Debug to check filtered results

      // Update displayed data
      setDisplayedFileData(filteredFileData);
      setDisplayedVulnerabilityData(filteredVulnerabilityData);

      // Reset pagination to the first page after search
      setFilePage(1);
      setVulnPage(1);
    } else {
      // If search is cleared, reset to original data
      setDisplayedFileData(fileData);
      setDisplayedVulnerabilityData(vulnerabilityData);

      // Reset pagination when search is cleared
      setFilePage(1);
      setVulnPage(1);
    }
  };

  const handleViewClick = (data) => {
    // Combine the data and recommendedFixes into a single object
    const combinedData = {
      ...data, // This spreads the properties of the data object
      recommendedFixes, // Add recommendedFixes to the combined object
    };

    // Set the combined data and open the modal
    setSelectedData(combinedData);
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
  async function downloadPDF() {
    // Define the data to be sent to the backend
    const requestData = {
      data: {
        fileData: fileData,
        vulnerabilityData: vulnerabilityData,
      },
      type: "PDF",
    };

    try {
      // Send POST request to the backend
      const response = await axios.post(
        "https://crypta-bwgaebf7acgrdufv.southindia-01.azurewebsites.net/api/download",
        requestData,
        {
          responseType: "blob", // Important for handling file downloads
        }
      );

      // Create a Blob from the response
      const blob = new Blob([response.data], { type: "application/pdf" });

      // Create a link element
      const link = document.createElement("a");
      link.href = URL.createObjectURL(blob);
      link.download = "report.pdf"; // You can set the filename here

      // Append to the DOM and click the link to trigger download
      document.body.appendChild(link);
      link.click();

      // Remove the link after download
      document.body.removeChild(link);
    } catch (error) {
      console.error("Error generating PDF:", error);
    }
  }

  // Generate Excel report
  const downloadWORD = () => {
    const wb = XLSX.utils.book_new();
    const fileSheet = XLSX.utils.json_to_sheet(fileData);
    const vulnerabilitySheet = XLSX.utils.json_to_sheet(vulnerabilityData);
    XLSX.utils.book_append_sheet(wb, fileSheet, "File Details");
    XLSX.utils.book_append_sheet(
      wb,
      vulnerabilitySheet,
      "Vulnerability Details"
    );
    const wbout = XLSX.write(wb, { bookType: "xlsx", type: "array" });
    saveAs(
      new Blob([wbout], { type: "application/octet-stream" }),
      "report.xlsx"
    );
  };

  // Generate CSV report
  const downloadCSV = () => {
    const csvContent = [
      ["File", "Type", "Size", "Vulnerability"],
      ...fileData.map(({ file, type, size, vulnerability }) => [
        file,
        type,
        size,
        vulnerability,
      ]),
    ]
      .map((row) => row.join(","))
      .join("\n");
    const blob = new Blob([csvContent], { type: "text/csv;charset=utf-8;" });
    saveAs(blob, "report.csv");
  };

  const handleDownload = () => {
    switch (selectedFormat) {
      case "PDF":
        downloadPDF();
        break;
      case "WORD":
        downloadWORD();
        break;
      case "CSV":
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

  const exportJSON = () => {
    // Combine the data into a single object
    const combinedData = {
      fileData: fileData,
      vulnerabilityData: vulnerabilityData,
    };

    // Convert the combined data to a JSON string
    const jsonString = JSON.stringify(combinedData, null, 2); // Pretty-print with 2 spaces

    // Create a Blob from the JSON string
    const blob = new Blob([jsonString], { type: "application/json" });

    // Create a link element
    const link = document.createElement("a");
    link.href = URL.createObjectURL(blob);
    link.download = "data.json"; // Name of the file to be downloaded

    // Append to the DOM and click the link to trigger download
    document.body.appendChild(link);
    link.click();

    // Remove the link after download
    document.body.removeChild(link);
  };

  const exportXML = () => {
    // Implementation for exporting as XML
  };

  const exportTEXT = () => {
    // Implementation for exporting as TEXT
  };

  const exportMD = () => {
    // Implementation for exporting as MD
  };

  const handleExport = () => {
    switch (selectedExportFormat) {
      case "JSON":
        exportJSON();
        break;
      case "XML":
        exportXML();
        break;
      case "TEXT":
        exportTEXT();
        break;
      case "MD":
        exportMD();
        break;
      default:
        break;
    }
  };

  return (
    <div className="dashboard__container">
      <h1 className="dashboard__title">Dashboard</h1>
      <hr className="dashboard__separator" />

      <div className="dashboard__search-bar-container rounded-floating">
        <div className="dashboard__search-bar-wrapper">
          <FontAwesomeIcon
            icon={faSearch}
            size="lg"
            className="dashboard__search-icon floating-icon"
          />
          <input
            type="text"
            className="dashboard__search-bar floating"
            placeholder="Search files..."
            onChange={handleSearchChange}
            value={searchTerm}
          />
          <button className="dashboard__search-filter right-aligned">
            {searchTerm && (
              <button
                className="dashboard__search-clear"
                onClick={() => {
                  setSearchTerm("");
                  setDisplayedFileData(fileData); // Reset to original data
                  setDisplayedVulnerabilityData(vulnerabilityData); // Reset to original data
                }}
              >
                <FontAwesomeIcon icon={faTimes} size="lg" />
              </button>
            )}
            <FontAwesomeIcon icon={faFilter} size="lg" />
          </button>
        </div>
      </div>

      <h2>File Summary</h2>
      <div className="dashboard__card">
        <div className="dashboard__card-header">
          <div>File</div>
          <div>
            Type
            <button
              className="sort-button-custom"
              onClick={() => handleSort("type")}
            >
              <span className="icon-container">
                <FontAwesomeIcon
                  icon={
                    sortCriteria.key === "type" && sortCriteria.order === "asc"
                      ? faSortUp
                      : faSortDown
                  }
                  className="sort-icon"
                />
              </span>
            </button>
          </div>
          <div>
            Size
            <button
              className="sort-button-custom"
              onClick={() => handleSort("size")}
            >
              <span className="icon-container">
                <FontAwesomeIcon
                  icon={
                    sortCriteria.key === "size" && sortCriteria.order === "asc"
                      ? faSortUp
                      : faSortDown
                  }
                  className="sort-icon"
                />
              </span>
            </button>
          </div>
          <div>
            Vulnerability Count
            <button
              className="sort-button-custom"
              onClick={() => handleSort("vulnerability")}
            >
              <span className="icon-container">
                <FontAwesomeIcon
                  icon={
                    sortCriteria.key === "vulnerability" &&
                    sortCriteria.order === "asc"
                      ? faSortUp
                      : faSortDown
                  }
                  className="sort-icon"
                />
              </span>
            </button>
          </div>
        </div>

        <div className="dashboard__card-body">
          {currentFilePageData.map((data, index) => (
            <div key={index} className="dashboard__card-row">
              <div>{data.file}</div>
              <div>{data.type}</div>
              <div>{data.size}</div>
              <div>
                <div
                  className="vul_count"
                  style={{
                    backgroundColor: getVulnerabilityColor(data.vulnerability), // Background color based on the vulnerability count
                    padding: "5px 0", // Adjust padding as needed
                    borderRadius: "5px", // Optional: for rounded corners
                    display: "inline-block", // Makes the div fit the content size
                  }}
                >
                  {data.vulnerability}
                </div>
              </div>

              {/* Handle network data if available */}
              {data.network && Array.isArray(data.network) && (
                <div className="network-section">
                  <h4>Network Data:</h4>
                  <ul>
                    {data.network.map((networkItem, idx) => (
                      <li key={idx}>{networkItem}</li>
                    ))}
                  </ul>
                </div>
              )}
            </div>
          ))}
        </div>

        {/* Total Files */}
        <div className="total-files">Total Files: {fileData.length}</div>

        {/* Pagination Controls */}
        <div className="pagination-controls">
          <button
            className="pagination-btn"
            onClick={() => handleFilePageChange("prev")}
            disabled={filePage === 1}
          >
            <FontAwesomeIcon icon={faChevronLeft} />
          </button>

          {Array.from({ length: endFilePage - startFilePage + 1 }, (_, i) => {
            const pageNumber = startFilePage + i;
            return (
              <button
                key={pageNumber}
                className={`pagination-number ${
                  filePage === pageNumber ? "active" : ""
                }`}
                onClick={() => handleFilePageChange(pageNumber)}
              >
                {pageNumber}
              </button>
            );
          })}

          <button
            className="pagination-btn-r"
            onClick={() => handleFilePageChange("next")}
            disabled={filePage === totalFilePages}
          >
            <FontAwesomeIcon icon={faChevronRight} />
          </button>
        </div>
      </div>

      {/* Vulnerability Information Card */}
      <h2>Vulnerability Summary</h2>
      <div className="dashboard_v_card">
        <div className="dashboard_v_card-header">
          <div>File</div>
          <div>Vulnerability Type</div>
          <div>Indicators of Compromise</div>
        </div>
        <div className="dashboard_v_card-body">
          {currentVulnerabilityPageData.map((data, index) => (
            <div key={index} className="dashboard_v_card-row">
              <div>{data.file}</div>
              <div>{data.type}</div>
              <div>
                <button
                  className="dashboard__view-btn"
                  onClick={() => handleViewClick(data)}
                >
                  View
                </button>
              </div>

              {/* Handle network data if available in the vulnerability section */}
              {data.network && Array.isArray(data.network) && (
                <div className="network-section">
                  <h4>Network Data:</h4>
                  <ul>
                    {data.network.map((networkItem, idx) => (
                      <li key={idx}>{networkItem}</li>
                    ))}
                  </ul>
                </div>
              )}
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
            onClick={() => handleVulnPageChange("prev")}
            disabled={vulnPage === 1}
          >
            <FontAwesomeIcon icon={faChevronLeft} />
          </button>

          {Array.from({ length: endVulnPage - startVulnPage + 1 }, (_, i) => {
            const pageNumber = startVulnPage + i;
            return (
              <button
                key={pageNumber}
                className={`pagination-number ${
                  vulnPage === pageNumber ? "active" : ""
                }`}
                onClick={() => handleVulnPageChange(pageNumber)}
              >
                {pageNumber}
              </button>
            );
          })}

          <button
            className="pagination-btn-r"
            onClick={() => handleVulnPageChange("next")}
            disabled={vulnPage === totalVulnPages}
          >
            <FontAwesomeIcon icon={faChevronRight} />
          </button>
        </div>
      </div>

      {/* Modal */}
      <ModalPage
        isOpen={isModalOpen}
        onClose={handleCloseModal}
        data={selectedData}
      />

      <div className="dashboard__alert-section">
        <h2 className="dashboard__alert-title">Alerts</h2>
        <hr className="dashboard__alert-separator" />

        {/* Loop through the grouped alerts by type */}
        {Object.keys(groupedAlerts).map((type, index) => (
          <div key={index} className="dashboard__alert-group">
            <h3 className="dashboard__alert-type">{type} Alerts</h3>{" "}
            {/* Alert type header */}
            <ul className="dashboard__alert-list">
              {groupedAlerts[type]
                .slice(0, showAllAlerts ? groupedAlerts[type].length : 3)
                .map((detail, idx) => (
                  <li key={idx} className="dashboard__alert-item">
                    {detail} {/* Display alert details */}
                  </li>
                ))}
            </ul>
          </div>
        ))}

        {/* Show more/less button if needed */}
        {alerts.length > 3 && (
          <button
            className="dashboard__show-more"
            onClick={() => setShowAllAlerts(!showAllAlerts)}
          >
            {showAllAlerts ? "Show Less" : "Show More"}
          </button>
        )}
      </div>

      <div className="dashboard__buttons-container">
        {/* Download Button Section */}
        <div className="dashboard__download-section">
          <button className="dashboard__download-btn" onClick={handleDownload}>
            Download Report{" "}
            <FontAwesomeIcon
              icon={faArrowDown}
              className="dashboard__download-icon"
            />
          </button>

          {/* Download Dropdown */}
          <div className="dashboard__dropdown">
            <button onClick={toggleMenu} className="dashboard__dropdown-toggle">
              {selectedFormat}{" "}
              <FontAwesomeIcon
                icon={faCaretDown}
                className="dashboard__dropdown-icon"
              />
            </button>
            {isOpen && (
              <div className="dashboard__dropdown-menu">
                <div onClick={() => selectFormat("PDF")}>PDF</div>
                <div onClick={() => selectFormat("CSV")}>CSV</div>
                <div onClick={() => selectFormat("WORD")}>WORD</div>
              </div>
            )}
          </div>
        </div>

        {/* Export Button Section */}
        <div className="dashboard__export-section">
          <button className="dashboard__export-btn" onClick={handleExport}>
            Export Analysis{" "}
            <FontAwesomeIcon
              icon={faShareSquare}
              className="dashboard__export-icon"
            />
          </button>

          {/* Export Dropdown */}
          <div className="dashboard__dropdown">
            <button
              onClick={toggleExportMenu}
              className="dashboard__dropdown-toggle"
            >
              {selectedExportFormat}{" "}
              <FontAwesomeIcon
                icon={faCaretDown}
                className="dashboard__dropdown-icon"
              />
            </button>
            {isExportMenuOpen && (
              <div className="dashboard__dropdown-export-menu">
                <div onClick={() => selectExportFormat("JSON")}>JSON</div>
                <div onClick={() => selectExportFormat("XML")}>XML</div>
                <div onClick={() => selectExportFormat("MD")}>MD</div>
                <div onClick={() => selectExportFormat("TEXT")}>TEXT</div>
              </div>
            )}
          </div>
        </div>
      </div>
      <h1 className="graph__title">Graphs</h1>
      <hr className="dashboard__separator" />
      <div>
        <DashboardCharts
          fileData={fileData}
          vulnerabilityData={vulnerabilityData}
        />
      </div>
    </div>
  );
};

export default Dashboard;
