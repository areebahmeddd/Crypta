// Layout.js
import React, { useState } from 'react';
import chatbotIcon from '../assets/logo/chat.png'; // Adjust the path
import searchLogo from '../assets/logo/Chatbotupload.png'; // Import your logo image
import "../styles/Chatbot.css";

const Layout = ({ children }) => {
  const [showChatbot, setShowChatbot] = useState(false);
  const [searchQuery, setSearchQuery] = useState('');

  const toggleChatbot = () => {
    setShowChatbot(!showChatbot);
  };

  const handleSearchChange = (e) => {
    setSearchQuery(e.target.value);
  };

  return (
    <div>
      {/* Page content */}
      {children}

      {/* Chatbot Icon */}
      <div className="chatbot-icon" onClick={toggleChatbot}>
        <img src={chatbotIcon} alt="Chatbot Icon" />
      </div>

      {/* Chatbot Popup */}
      {showChatbot && (
        <div className="chatbot-popup">
          <div className="chatbot-header">
            <h3>Chat</h3>
            <button onClick={toggleChatbot}>✖</button>
          </div>
          <div className="chatbot-content">
            <p>Welcome! How can I assist you?</p>
          </div>
          <div className="chatbot-search">
            <input
              type="text"
              placeholder="Search..."
              value={searchQuery}
              onChange={handleSearchChange}
            />
            <img src={searchLogo} alt="Search Logo" className="search-logo" /> {/* Use your logo image */}
          </div>
        </div>
      )}
    </div>
  );
};

export default Layout;
