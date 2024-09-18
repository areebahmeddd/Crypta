import React from "react";
import "../styles/About.css";

const About = () => {
  return (
    <div className="about-page">
      <div className="about-header">
        <h1>Welcome to Crypta</h1>
      </div>

      <div className="about-content">
        <section className="about-section">
          <h2>What is Crypta?</h2>
          <p>
            An automated digital forensics and incident response system designed
            for anomaly detection and pattern recognition across system data and
            network activity. The tool integrates AI/ML models to classify
            system risk levels, identify indicators of compromise (IoCs), and
            generate actionable insights from forensic disk images, memory
            dumps, and network traffic.
          </p>
          <p>
            Additionally, the tool supports live drive detection, allowing
            investigators to connect drives and perform real-time forensic
            analysis. It also features a chatbot that provides detailed
            explanations of detected anomalies, offering further insights.
          </p>
        </section>

        <section className="about-section interactive-section">
          <h2>Why Crypta?</h2>
          <ul className="interactive-list">
            <li>
              <strong>Automated Forensic Data Collection:</strong> Automates FTK
              Imager, Volatility, RegRipper, and Sysinternals Suite through
              Python libraries (PyEWF, MemProcFS, Regipy, and PSUtil) for
              forensic images, memory dumps, registry hives, and background
              processes.
            </li>
            <li>
              <strong>Network Traffic Analysis:</strong> Leverages Wireshark and
              Scapy to analyze packet captures and identify suspicious network
              activities.
            </li>
            <li>
              <strong>IoC Identification:</strong> Utilizes custom YARA rules
              and MISP databases for detecting file anomalies and correlating
              known IoCs.
            </li>
            <li>
              <strong>AI/ML Integration:</strong> Implements TensorFlow models
              for anomaly detection and risk classification, offering
              investigators prioritized analysis of critical artifacts.
            </li>
            <li>
              <strong>Cross-Platform Dashboards:</strong> Provides real-time
              data visualization, interactive timelines, and detailed reports
              with export options in PDF, JSON, and CSV formats.
            </li>
            <li>
              <strong>Scalable Architecture:</strong> Built with FastAPI,
              Next.js, and Flutter, ensuring high performance and easy
              deployment across environments.
            </li>
          </ul>
        </section>
      </div>
    </div>
  );
};

export default About;
