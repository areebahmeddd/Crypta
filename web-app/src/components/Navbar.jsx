import React from 'react';
import { FontAwesomeIcon } from '@fortawesome/react-fontawesome';
import { faGithub } from '@fortawesome/free-brands-svg-icons';
import { faArrowCircleDown } from '@fortawesome/free-solid-svg-icons';
import '../styles/Navbar.css'; // Import the CSS file for Navbar styles

// Import the logo image
import logo from '../assets/filelogo/logo.png';

function Navbar() {
  return (
    <div className="navbar">
      <div className="navbar-container">
        {/* Navbar left side */}
        <div className="navbar-left">
          <a href="/" className="logo-link">
            <img src={logo} alt="Logo" className="logo" />
          </a>
        </div>

        {/* Navbar links */}
        <div className="navbar-links">
          <a href="#about" className="navbar-link">About</a>
          <a href="#team" className="navbar-link">Team</a>
          <a href="#contact" className="navbar-link">Contact</a>
        </div>

        {/* Navbar right side */}
        <div className="navbar-right">
        <a href="/path-to-your-file" download className="download-link">
  <span>Download</span>
  <FontAwesomeIcon icon={faArrowCircleDown} style={{ marginLeft: '8px' }} />
</a>
          <a href="https://github.com/areebahmeddd/Crypta" target="_blank" rel="noopener noreferrer" className="social-link">
            <FontAwesomeIcon icon={faGithub} />
          </a>
        </div>
      </div>
    </div>
  );
}

export default Navbar;
