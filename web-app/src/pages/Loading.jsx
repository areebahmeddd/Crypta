import React, { useState, useEffect } from "react";
import "../styles/Loading.css";

const LoadingPage = () => {
  const [displayedText, setDisplayedText] = useState("");
  const [textIndex, setTextIndex] = useState(0);
  const [charIndex, setCharIndex] = useState(0);
  const [isDeleting, setIsDeleting] = useState(false);

  // Texts to display in the loading screen
  const texts = [
    "Hacking the matrix…",
    "Quantum data prep…",
    "Configuring AI…",
    "Unlocking secrets…",
    "Syncing systems…",
    "Unleashing wizards…",
    "Calibrating overmind…",
    "Crunching numbers…",
    "Taming data…",
    "Transmitting bytes…",
  ];

  useEffect(() => {
    const handleTypewriterEffect = () => {
      const currentText = texts[textIndex];

      // Update displayed text based on typing or deleting
      setDisplayedText(
        isDeleting
          ? currentText.slice(0, charIndex - 1)
          : currentText.slice(0, charIndex + 1)
      );
      setCharIndex((prev) => (isDeleting ? prev - 1 : prev + 1));

      // Switch to deleting mode after typing is complete
      if (!isDeleting && charIndex === currentText.length) {
        setTimeout(() => setIsDeleting(true), 1000);
      }
      // Move to the next text after deleting
      else if (isDeleting && charIndex === 0) {
        setIsDeleting(false);
        setTextIndex((prev) => (prev + 1) % texts.length);
      }
    };

    const typingSpeed = isDeleting ? 40 : 100;
    const typingInterval = setTimeout(handleTypewriterEffect, typingSpeed);

    // Cleanup timeout on component unmount
    return () => clearTimeout(typingInterval);
  }, [charIndex, isDeleting, textIndex]);

  return (
    <div className="loading-page">
      <div className="loading-container">
        <div className="loading-text glitch">
          <p>{displayedText}</p>
        </div>
        <div className="environment"></div> {/* Blurred background */}
      </div>
    </div>
  );
};

export default LoadingPage;
