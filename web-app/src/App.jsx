import React from "react";
import { BrowserRouter as Router, Route, Routes } from "react-router-dom";
import Home from "./pages/Home.jsx";
import Navbar from "./components/Navbar.jsx";
import Rules from "./pages/Rules.jsx";
import Dashboard from "./pages/Dashboard";
function App() {
  return (
    <Router>
      <div>
        <Navbar /> {/* Add Navbar here */}
        <Routes>
          <Route path="/" element={<Home />} />
          <Route path="/rules" element={<Rules />} />
          <Route path="/dashboard" element={<Dashboard />} />
        </Routes>
      </div>
    </Router>
  );
}

export default App;
