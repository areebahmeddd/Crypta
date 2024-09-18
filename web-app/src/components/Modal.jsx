import React, { useState } from "react";
import "../styles/Modal.css";
import { FontAwesomeIcon } from "@fortawesome/react-fontawesome";
import {
  faChevronLeft,
  faChevronRight,
} from "@fortawesome/free-solid-svg-icons";

const ModalPage = ({ isOpen, onClose, data }) => {
  const [filePage, setFilePage] = useState(1);
  const rowsPerPage = 3;
  const indicators = data?.indicators || [];
  const totalFilePages = Math.ceil(indicators.length / rowsPerPage);
  const [showAllFixes, setShowAllFixes] = useState(false);
  const [showAllFixesGlobal, setShowAllFixesGlobal] = useState(false);
  const recommendedFixes = data?.recommendedFixes || [];

  // Calculate the start and end page numbers for the pagination
  const startPage = Math.max(1, filePage - 1);
  const endPage = Math.min(totalFilePages, filePage + 1);

  // Handle page navigation for the indicators table
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

  // Toggle the visibility of more/less fixes
  const toggleShowMore = (index) => {
    setShowAllFixes((prevState) => ({
      ...prevState,
      [index]: !prevState[index],
    }));
  };

  // Return the CSS class based on the severity level
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

  // Return null if the modal is not open
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
        <div className="dashboard_r_alert-section">
          <h2 className="dashboard_r_alert-title">Recommended Fixes</h2>
          <hr className="dashboard_r_alert-separator" />
          {recommendedFixes.length > 0 ? (
            recommendedFixes
              .slice(0, showAllFixesGlobal ? recommendedFixes.length : 3)
              .map((fixItem, index) => (
                <div key={index} className="dashboard_r_alert-group">
                  <div className="dashboard_r_alert-issue">
                    <div className="dashboard_r_alert-issue-row">
                      <h3 className="dashboard_r_alert-issue-title">
                        {index + 1}. Issue:
                      </h3>
                      <p className="dashboard_r_alert-issue-description">
                        {fixItem.issue}
                      </p>
                    </div>
                  </div>
                  <div className="dashboard_r_alert-fixes">
                    <h3 className="dashboard_r_alert-fixes-title">Actions</h3>
                    <ul className="dashboard_fix_alert-list">
                      {fixItem.fix
                        .slice(0, showAllFixes[index] ? fixItem.fix.length : 3)
                        .map((fixDetail, idx) => (
                          <li key={idx} className="dashboard_r_alert-item">
                            {fixDetail}
                          </li>
                        ))}
                    </ul>
                    {fixItem.fix.length > 3 && (
                      <button
                        className="dashboard__show-more"
                        onClick={() => toggleShowMore(index)}
                      >
                        {showAllFixes[index] ? "Show Less" : "Show More"}
                      </button>
                    )}
                  </div>
                </div>
              ))
          ) : (
            <p>No recommended fixes available.</p>
          )}
          {recommendedFixes.length > 3 && (
            <button
              className="dashboard__show-more"
              onClick={() => setShowAllFixesGlobal(!showAllFixesGlobal)}
            >
              {showAllFixesGlobal ? "Show Less" : "Show More"}
            </button>
          )}
        </div>
      </div>
    </div>
  );
};

export default ModalPage;
