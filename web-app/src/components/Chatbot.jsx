// Layout.js
import React from 'react';
import chatbotIcon from '../assets/logo/chat.png'; // Adjust the path
import "../styles/Chatbot.css";

const Layout = ({ children }) => {
  const [showChatbot, setShowChatbot] = React.useState(false);

  const toggleChatbot = () => {
    setShowChatbot(!showChatbot);
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
        </div>
      )}
    </div>
  );
};

export default Layout;
