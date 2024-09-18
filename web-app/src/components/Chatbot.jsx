import React, { useState } from "react";
import chatbotIcon from "../assets/logo/chat.png";
import searchLogo from "../assets/logo/send.png";
import "../styles/Chatbot.css";

const Layout = ({ children }) => {
  const [showChatbot, setShowChatbot] = useState(false);
  const [searchQuery, setSearchQuery] = useState("");

  // Function to toggle the visibility of the chatbot
  const toggleChatbot = () => {
    setShowChatbot(!showChatbot);
  };

  // Function to handle changes in the search input field
  const handleSearchChange = (e) => {
    setSearchQuery(e.target.value);
  };

  return (
    <div>
      {/* Render the children components */}
      {children}

      {/* Chatbot icon that toggles the chatbot visibility */}
      <div className="chatbot-icon" onClick={toggleChatbot}>
        <img src={chatbotIcon} alt="Chatbot Icon" />
      </div>

      {/* Conditionally render the chatbot popup based on the showChatbot state */}
      {showChatbot && (
        <div className="chatbot-popup">
          {/* Header section of the chatbot with close button */}
          <div className="chatbot-header">
            <h3>Chat</h3>
            <button onClick={toggleChatbot}>✖</button>
          </div>
          {/* Content area of the chatbot */}
          <div className="chatbot-content">
            <p>Welcome! How can I assist you?</p>
          </div>
          {/* Search input and logo */}
          <div className="chatbot-search">
            <input
              type="text"
              placeholder="Message..."
              value={searchQuery}
              onChange={handleSearchChange}
            />
            <img src={searchLogo} alt="Search Logo" className="search-logo" />
          </div>
        </div>
      )}
    </div>
  );
};

export default Layout;
