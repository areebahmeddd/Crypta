import React, { useState, useEffect } from "react";
import { useNavigate, useLocation } from "react-router-dom";
import "../styles/Rules.css";
import uploadIcon from "../assets/upload.png";
import defaultRulesLogo from "../assets/logo/defaultIcon.png";
import defaultRulesFile from "../assets/static/security.yara";

function Rules() {
  const navigate = useNavigate();
  const location = useLocation(); // Use location to access passed state
  const [selectedOption, setSelectedOption] = useState("");
  const [dragging, setDragging] = useState(false);
  const [inputKey, setInputKey] = useState(Date.now()); // Unique key for file input
  const [rulesFile, setRulesFile] = useState(null); // State for selected file
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState("");

  // Access the files passed from the homepage
  useEffect(() => {
    if (location.state && location.state.files) {
      const files = location.state.files;
      console.log("Files received from homepage:", files);
      if (files.length > 0) {
        setRulesFile(files[0]); // Set the first file (or modify to handle multiple files)
        setSelectedOption("drag-drop"); // Update selected option
      }
    }
  }, [location.state]);

  const handleDragDropOption = () => {
    setSelectedOption("drag-drop");
  };

  const onDragOver = (e) => {
    e.preventDefault();
    e.stopPropagation();
    setDragging(true);
  };

  const onDragLeave = (e) => {
    e.preventDefault();
    e.stopPropagation();
    setDragging(false);
  };

  const onDrop = (e) => {
    e.preventDefault();
    e.stopPropagation();
    setDragging(false);
    if (e.dataTransfer.files.length > 0) {
      handleDragDropOption();
      setRulesFile(e.dataTransfer.files[0]); // Set the dropped file
    }
  };

  const onChange = (e) => {
    if (e.target.files.length > 0) {
      handleDragDropOption();
      setRulesFile(e.target.files[0]); // Set the selected file
    }
  };

  const handleFileSelection = () => {
    // Create a File object for the default rules file
    const defaultFile = new File(
      [defaultRulesFile], // File content, should be binary data or text content
      "security.yara", // File name
      { type: "text/plain" } // File type
    );

    // Set the default rules file as selected
    setRulesFile(defaultFile);
    setSelectedOption("default-file");
  };

  const onSubmit = (e) => {
    e.preventDefault();
    // Handle form submission if needed
  };

  const handleCancel = () => {
    setSelectedOption("");
    setRulesFile(null); // Clear the selected file
    navigate("/"); // Navigate to the home page or previous page
  };
  const handleAnalyze = async () => {
    if (selectedOption || rulesFile) {
      setLoading(true); // Start loading state
      setError(""); // Clear any previous errors

      console.log("Selected Files:", rulesFile);
      try {
        const formData = new FormData();

        // Append files passed from the homepage
        if (location.state && location.state.files) {
          location.state.files.forEach((file, index) => {
            formData.append(`file${index}`, file);
          });
        }
        // Append the selected YARA rules file
        if (rulesFile) {
          formData.append("rulesFile", rulesFile);
        }

        for (let [key, value] of formData.entries()) {
          if (value instanceof File) {
            console.log(`${key}:`);
            console.log(`  Name ${value.name}`);
            console.log(`  Size ${(value.size / 1024).toFixed(2)} KB`);
            console.log(`  Type ${value.type}`);
            console.log(
              `  Last Modified: ${
                value.lastModifiedDate
                  ? value.lastModifiedDate.toLocaleDateString()
                  : "N/A"
              }`
            );
          } else {
            console.log(`${key}: ${value}`);
          }
        }
        const response = await fetch("http://127.0.0.1:8080/api/upload", {
          method: "POST",
          body: formData,
        });

        if (response.ok) {
          const responseData = await response.json();
          console.log("Response from backend:", result);

          if (responseData && responseData.processedData) {
            navigate("/dashboard", {
              state: {
                processingMethod: selectedOption,
                rulesFile: rulesFile ? rulesFile.name : null,
                processedData: responseData.processedData, // Pass the processed data
              },
            });
          } else {
            setError("No processed data received from the server.");
            alert("No processed data received from the server.");
          }
        } else {
          const errorData = await response.json();
          setError(`Error: ${errorData.message || "Failed to upload files"}`);
          alert(`Error: ${errorData.message || "Failed to upload files"}`);
        }
      } catch (error) {
        setError(`Error: ${error.message}`);
        alert(`Error: ${error.message}`);
      } finally {
        setLoading(false); // End loading state
      }
    } else {
      setError("Please select an option or file first.");
      alert("Please select an option or file first.");
    }
  };

  return (
    <div className="options-containers">
      <div className="options-wrappers">
        <h2 className="headers">Upload YARA Rules</h2>
        <div className="optionss">
          <div
            className={`upload-boxs ${dragging ? "dragging" : ""}`}
            onDrop={onDrop}
            onDragOver={onDragOver}
            onDragLeave={onDragLeave}
          >
            <form onSubmit={onSubmit}>
              <div className="upload-areas">
                <label htmlFor="file-upload" className="upload-labels">
                  <img
                    src={uploadIcon}
                    alt="Upload Icon"
                    className="upload-icons"
                  />
                  <span className="upload-texts">Drag & Drop Your File</span>
                  <span className="upload-texts choose-files">Choose File</span>
                  <input
                    id="file-upload"
                    type="file"
                    className="hidden"
                    key={inputKey}
                    onChange={onChange}
                    multiple
                  />
                </label>
              </div>
            </form>
          </div>
          <span className="or">————— OR —————</span>
          <div className="default-rules">
            <img
              src={defaultRulesLogo}
              alt="Default Rules Logo"
              className="default-rules-logo"
            />
            <div className="default-rules-info">
              <p>
                <code>security.yara</code>
              </p>
              <div
                className={`default-rules-option ${
                  selectedOption === "default-file" ? "selected" : ""
                }`}
                onClick={handleFileSelection}
              >
                <span className="radio-button">
                  {selectedOption === "default-file" && (
                    <span className="radio-inner"></span>
                  )}
                </span>
                {selectedOption === "default-file"
                  ? "Default Rules"
                  : "Default Rules"}
              </div>
            </div>
          </div>
        </div>
        <div className="buttons">
          <button className="cancel-buttons" onClick={handleCancel}>
            Back
          </button>
          <button
            className="submit-buttons"
            onClick={handleAnalyze}
            disabled={loading}
          >
            Analyze
          </button>
        </div>
      </div>
      <div className={`file-infoo ${!rulesFile ? "hidden" : ""}`}>
        {rulesFile ? (
          <div className="file-details">
            <div>
              <div className="name">
                <strong>Name</strong>
              </div>
              <div>{rulesFile.name}</div>
            </div>
            <div>
              <div className="size">
                <strong>Size</strong>
              </div>
              <div>{(rulesFile.size / 1024).toFixed(2)} KB</div>
            </div>
            <div>
              <div className="type">
                <strong>Type</strong>
              </div>
              <div>{rulesFile.type}</div>
            </div>
            <div>
              <div className="modify">
                <strong>Last Modified</strong>
              </div>
              <div>
                {rulesFile.lastModifiedDate
                  ? rulesFile.lastModifiedDate.toLocaleDateString()
                  : "N/A"}
              </div>
            </div>
          </div>
        ) : null}
      </div>
    </div>
  );
}

export default Rules;
