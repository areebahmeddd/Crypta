import React, { useState, useEffect } from "react";
import { useNavigate, useLocation } from "react-router-dom";
import axios from "axios";
import "../styles/Rules.css";
import uploadIcon from "../assets/upload.png";
import defaultRulesLogo from "../assets/logo/defaultIcon.png";
import defaultRulesFile from "../assets/static/security.yara";

function Rules() {
  const navigate = useNavigate();
  const location = useLocation();
  const [selectedOption, setSelectedOption] = useState("");
  const [dragging, setDragging] = useState(false);
  const [inputKey, setInputKey] = useState(Date.now());
  const [rulesFile, setRulesFile] = useState(null);
  const [loading, setLoading] = useState(false);
  const [errorMessage, setErrorMessage] = useState("");

  // Update state when files are received from the previous page
  useEffect(() => {
    if (location.state && location.state.files) {
      const files = location.state.files;
      console.log("Files from Home: ", files);
      if (files.length > 0) {
        setSelectedOption("drag-drop");
      }
    }
  }, [location.state]);

  // Set the option to 'drag-drop' when a drag-and-drop action is initiated
  const handleDragDropOption = () => {
    setSelectedOption("drag-drop");
  };

  // Handle drag-over event to show visual feedback
  const onDragOver = (e) => {
    e.preventDefault();
    e.stopPropagation();
    setDragging(true);
  };

  // Handle drag-leave event to remove visual feedback
  const onDragLeave = (e) => {
    e.preventDefault();
    e.stopPropagation();
    setDragging(false);
  };

  // Handle file drop event and set the rules file
  const onDrop = (e) => {
    e.preventDefault();
    e.stopPropagation();
    setDragging(false);
    if (e.dataTransfer.files.length > 0) {
      handleDragDropOption();
      setRulesFile(e.dataTransfer.files[0]);
    }
  };

  // Handle file selection via input change event
  const onChange = (e) => {
    if (e.target.files.length > 0) {
      handleDragDropOption();
      setRulesFile(e.target.files[0]);
    }
  };

  // Set the default file and update the selected option
  const handleFileSelection = () => {
    const defaultFile = new File([defaultRulesFile], "security.yara", {
      type: "text/plain",
    });
    setRulesFile(defaultFile);
    setSelectedOption("default-file");
  };

  // Prevent default form submission behavior
  const onSubmit = (e) => {
    e.preventDefault();
  };

  // Reset state and navigate back to the homepage
  const handleCancel = () => {
    setSelectedOption("");
    setRulesFile(null);
    navigate("/");
  };

  // Handle file analysis submission
  const handleAnalyze = async () => {
    if (selectedOption || rulesFile) {
      setLoading(true);
      setErrorMessage("");
      try {
        const formData = new FormData();

        if (location.state && location.state.files) {
          location.state.files.forEach((fileData) => {
            formData.append("uploadedFiles", fileData.file);
          });
        }

        if (rulesFile) {
          formData.append("yaraFile", rulesFile);
        }
        
        console.log("Uploaded Files: ", location.state.files);
        console.log("Rules File: ", rulesFile);
        const response = await axios.post(
          "http://127.0.0.1:8000/api/upload",
          formData,
          {
            headers: {
              "Content-Type": "multipart/form-data",
            },
          }
        );

        if (response.status === 200) {
          const responseData = response.data;
          console.log("Response from Backend: ", responseData);
          if (responseData && responseData.processedData) {
            navigate("/dashboard", {
              state: {
                processingMethod: selectedOption,
                rulesFile: rulesFile ? rulesFile.name : null,
                processedData: responseData.processedData,
                filesFromHome: location.state.files,
              },
            });
          }
        } else {
          setErrorMessage(
            `Error: ${response.data.message || "Failed to upload files"}`
          );
        }
      } catch (error) {
        setErrorMessage(`Error: ${error.message}`);
      } finally {
        setLoading(false);
      }
    } else {
      setErrorMessage("Please select a file to analyze.");
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
            disabled={!rulesFile}
          >
            Analyze
          </button>
        </div>
      </div>
      <div className={`file-infoo ${!rulesFile ? "hidden" : ""}`}>
        {rulesFile ? (
          <div className="files-details">
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
