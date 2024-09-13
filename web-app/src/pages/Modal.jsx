import React, { useState } from "react";
import "../styles/Modal.css"; // Ensure this path is correct
import { FontAwesomeIcon } from "@fortawesome/react-fontawesome";
import {
  faChevronLeft,
  faChevronRight,
} from "@fortawesome/free-solid-svg-icons";

const ModalPage = ({ isOpen, onClose, data }) => {
  const [filePage, setFilePage] = useState(1);
  const rowsPerPage = 5;
  const indicators = data?.indicators || [];
  const totalFilePages = Math.ceil(indicators.length / rowsPerPage);
  const [showAllFixes, setShowAllFixes] = useState(false); // State to toggle recommended fixes
  // const recommendedFixes = data?.recommendedFixes || [];

  // Mock data for recommended fixes
  const recommendedFixes = [
    {
      id: 1,
      message:
        "Critical system update required. Please update your software to ensure security.",
    },
    {
      id: 2,
      message:
        "Unauthorized access attempt detected. Review your security settings immediately.",
    },
    {
      id: 3,
      message:
        "New vulnerability discovered in your application. Apply the latest patch to address the issue.",
    },
    {
      id: 4,
      message:
        "Backup failure detected. Ensure your backup system is functioning properly to avoid data loss.",
    },
    {
      id: 5,
      message:
        "High CPU usage alert. Check for any processes that might be consuming excessive resources.",
    },
    // More mock data...
  ];

  // Calculate page numbers to show
  const maxPageNumbersToShow = 2;
  const startPage = Math.max(1, filePage - 1); // Show the current page and the previous one
  const endPage = Math.min(totalFilePages, filePage + 1); // Show the current page and the next one

  const handleFilePageChange = (direction) => {
    if (direction === "next" && filePage < totalFilePages) {
      setFilePage(filePage + 1);
    } else if (direction === "prev" && filePage > 1) {
      setFilePage(filePage - 1);
    }
  };

  const displayedIndicators = indicators.slice(
    (filePage - 1) * rowsPerPage,
    filePage * rowsPerPage
  );
  const displayedFixes = showAllFixes
    ? recommendedFixes
    : recommendedFixes.slice(0, 3);

  // Function to get the class name based on the level
  const getLevelClass = (level) => {
    switch (level) {
      case "High":
        return "level-high";
      case "Low-Medium":
        return "level-low-medium";
      case "Medium":
        return "level-medium";
      case "Low":
        return "level-low";
      default:
        return "";
    }
  };

  if (!isOpen) return null;

  return (
    <div className="modal-overlay">
      <div className="modal-content">
        <div className="modal-header">
          <h2>{data?.file || "File"} - IoC</h2>
          <button className="modal-close-btn" onClick={onClose}>
            Close
          </button>
        </div>
        <div className="indicator-card">
          <div className="indicator-table">
            <div className="indicator-table-header">
              <div>Level</div>
              <div>Type</div>
              <div>Triggered Actions</div>
            </div>
            <div className="indicator-table-body">
              {displayedIndicators.length > 0 ? (
                displayedIndicators.map((indicator, index) => (
                  <div key={index} className="indicator-table-row">
                    <div className="level_all">
                      {" "}
                      <div
                        className={`level-column ${getLevelClass(
                          indicator.level
                        )}`}
                      >
                        {indicator.level}
                      </div>
                    </div>
                    <div>{indicator.type}</div>
                    <div>{indicator.indicator}</div>
                  </div>
                ))
              ) : (
                <div className="no-indicators">No indicators to display</div>
              )}
            </div>
          </div>
          <div className="pagination-controls">
            <button
              className="pagination-btn"
              onClick={() => handleFilePageChange("prev")}
              disabled={filePage === 1}
            >
              <FontAwesomeIcon icon={faChevronLeft} />
            </button>
            {Array.from({ length: endPage - startPage + 1 }, (_, i) => {
              const pageNumber = startPage + i;
              return (
                <button
                  key={pageNumber}
                  className={`pagination-number ${
                    filePage === pageNumber ? "active" : ""
                  }`}
                  onClick={() => setFilePage(pageNumber)}
                >
                  {pageNumber}
                </button>
              );
            })}

            <button
              className="pagination-btn"
              onClick={() => handleFilePageChange("next")}
              disabled={filePage === totalFilePages}
            >
              <FontAwesomeIcon icon={faChevronRight} />
            </button>
          </div>
        </div>

        {/* Recommended Fixes Section */}
        <div className="dashboard__alert-section">
          <h2 className="dashboard__alert-title">Recommended Fixes</h2>
          <hr className="dashboard__alert-separator" />
          <ul className="dashboard__alert-list">
            {displayedFixes.map((fix) => (
              <li key={fix.id} className="dashboard__alert-item">
                {fix.message}
              </li>
            ))}
          </ul>
          {recommendedFixes.length > 3 && (
            <button
              className="dashboard__show-more"
              onClick={() => setShowAllFixes(!showAllFixes)}
            >
              {showAllFixes ? "Show Less" : "Show More"}
            </button>
          )}
        </div>
      </div>
    </div>
  );
};

export default ModalPage;
