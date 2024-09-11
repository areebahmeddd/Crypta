import React, { useState } from 'react';
import '../styles/Modal.css'; // Ensure this path is correct
import { FontAwesomeIcon } from '@fortawesome/react-fontawesome';
import { faChevronLeft, faChevronRight } from '@fortawesome/free-solid-svg-icons';

const ModalPage = ({ isOpen, onClose, data }) => {
  const [filePage, setFilePage] = useState(1);
  const rowsPerPage = 5;
  const indicators = data?.indicators || [];
  const totalFilePages = Math.ceil(indicators.length / rowsPerPage);

  // Calculate page numbers to show
  const maxPageNumbersToShow = 2;
  const startPage = Math.max(1, filePage - 1);  // Show the current page and the previous one
  const endPage = Math.min(totalFilePages, filePage + 1);  // Show the current page and the next one
  
  const handleFilePageChange = (direction) => {
    if (direction === 'next' && filePage < totalFilePages) {
      setFilePage(filePage + 1);
    } else if (direction === 'prev' && filePage > 1) {
      setFilePage(filePage - 1);
    }
  };

  const displayedIndicators = indicators.slice((filePage - 1) * rowsPerPage, filePage * rowsPerPage);

  if (!isOpen) return null;

  return (
    <div className="modal-overlay">
      <div className="modal-content">
        <div className="modal-header">
          <h2>{data?.file || 'File'} - IoC</h2>
          <button className="modal-close-btn" onClick={onClose}>Close</button>
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
                    <div>{indicator.level}</div>
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
              onClick={() => handleFilePageChange('prev')}
              disabled={filePage === 1}
            >
              <FontAwesomeIcon icon={faChevronLeft} />
            </button>
            {Array.from({ length: endPage - startPage + 1 }, (_, i) => {
    const pageNumber = startPage + i;
    return (
      <button
        key={pageNumber}
        className={`pagination-number ${filePage === pageNumber ? 'active' : ''}`}
        onClick={() => setFilePage(pageNumber)}
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
      </div>
    </div>
  );
};

export default ModalPage;
