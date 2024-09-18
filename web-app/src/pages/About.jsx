import React from "react";
import "../styles/About.css";

const About = () => {
  return (
    <div className="about-page">
      <div className="about-header">
        <h1>Welcome to Crypta</h1>
        <p>
          Empowering you to unlock deeper insights into file vulnerabilities
          with advanced technology.
        </p>
      </div>

      <div className="about-content">
        <section className="about-section">
          <h2>What is Crypta?</h2>
          <p>
            Crypta is a sophisticated platform designed to help individuals and
            organizations assess file vulnerabilities and understand data risks
            in a streamlined, effective way. With Crypta, you can easily scan
            files for potential risks and take the necessary steps to ensure
            security.
          </p>
        </section>

        <section className="about-section interactive-section">
          <h2>How Crypta Works</h2>
          <ul className="interactive-list">
            <li>
              <strong>File Analysis:</strong> Upload your files for real-time
              vulnerability analysis and risk assessment.
            </li>
            <li>
              <strong>Data Insights:</strong> Crypta provides clear, actionable
              insights on potential vulnerabilities, enabling smarter decisions.
            </li>
            <li>
              <strong>Advanced Security:</strong> Stay ahead of potential
              threats by leveraging Crypta's state-of-the-art vulnerability
              detection.
            </li>
          </ul>
        </section>

        <section className="about-section">
          <h2>Why Crypta?</h2>
          <p>
            We believe that data security should be both accessible and
            powerful. Whether you're an individual concerned about your files or
            an enterprise managing sensitive information, Crypta equips you with
            the tools needed to maintain your peace of mind. Our platform is
            designed with simplicity, reliability, and efficiency at its core.
          </p>
        </section>
      </div>
    </div>
  );
};

export default About;
