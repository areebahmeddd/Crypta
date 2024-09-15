import React, { useState, useEffect } from 'react';
import '../styles/Loading.css'; // Updated CSS for cyberpunk styling

const LoadingPage = () => {
    const [displayedText, setDisplayedText] = useState("");
    const [textIndex, setTextIndex] = useState(0);
    const [charIndex, setCharIndex] = useState(0);
    const [isDeleting, setIsDeleting] = useState(false);

    // Array of texts to loop through
    const texts = [
        "Loading futuristic data...",
        "Synchronizing systems...",
        "Activating dashboard interface...",
        "Finalizing connections...",
        "You're almost there..."
    ];

    useEffect(() => {
        const handleTypewriterEffect = () => {
            const currentText = texts[textIndex];
            
            if (isDeleting) {
                setDisplayedText(currentText.slice(0, charIndex - 1));
                setCharIndex(prev => prev - 1);
            } else {
                setDisplayedText(currentText.slice(0, charIndex + 1));
                setCharIndex(prev => prev + 1);
            }

            if (!isDeleting && charIndex === currentText.length) {
                setTimeout(() => setIsDeleting(true), 1000);
            } else if (isDeleting && charIndex === 0) {
                setIsDeleting(false);
                setTextIndex((prev) => (prev + 1) % texts.length);
            }
        };

        const typingSpeed = isDeleting ? 40 : 100;
        const typingInterval = setTimeout(handleTypewriterEffect, typingSpeed);

        return () => clearTimeout(typingInterval);
    }, [charIndex, isDeleting, textIndex]);

    return (
        <div className="loading-page">
            <div className="loading-container">
                <div className="loading-text glitch">
                    <p>{displayedText}</p>
                </div>
                <div className="environment"></div> {/* For the blurred background */}
            </div>
        </div>
    );
};

export default LoadingPage;
