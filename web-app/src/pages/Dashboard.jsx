import React from "react";
import { useLocation } from "react-router-dom";
import "../styles/Dashboard.css";

function Dashboard() {
  const location = useLocation();
  const processingMethod = location.state?.processingMethod;

  return (
    <div className="dashboard-container">
      <h1>Dashboard</h1>
      {processingMethod === "default" && (
        <div className="default-processing">
          <h2>Default Processing</h2>
          {/* Render default processing components here */}
        </div>
      )}
      {processingMethod === "drag-drop" && (
        <div className="drag-drop-processing">
          <h2>Drag and Drop Processing</h2>
          {/* Render drag and drop processing components here */}
        </div>
      )}
    </div>
  );
}

export default Dashboard;
