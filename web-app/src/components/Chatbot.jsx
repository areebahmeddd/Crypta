import React, { useState } from "react";
import chatbotIcon from "../assets/logo/chat.png";
import attachmentIcon from "../assets/logo/attachment.png";
import sendIcon from "../assets/logo/send.png";
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

  // Function to handle sending a message
  const handleSendMessage = () => {
    // Implement the logic to send the message
    console.log("Message sent:", searchQuery);
    setSearchQuery(""); // Clear the input field after sending the message
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
          <div className="chat-nav">
            <p>Chat</p>
            <button onClick={toggleChatbot}>✖</button>
          </div>
          <div className="chat-header">
            <p>Welcome!</p>
            <p>How can i assist you today?</p>
          </div>
          <div className="input-container">
            <div className="icon-div">
              <img src={attachmentIcon} alt="attach" className="icon" />
            </div>
            <textarea
              className="inp"
              placeholder="Message..."
              rows="1"
              value={searchQuery}
              onChange={handleSearchChange}
            ></textarea>
            <div className="send icon-div" onClick={handleSendMessage}>
              <img src={sendIcon} alt="send" className="icon" />
            </div>
          </div>
        </div>
      )}
    </div>
  );
};

export default Layout;
