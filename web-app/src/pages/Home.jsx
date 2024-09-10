import React, { useState } from "react";
import axios from "axios";
import { useNavigate } from "react-router-dom";
import "../styles/Home.css";
import uploadIcon from "../assets/upload.png";
import fileIcons from "../assets/fileIcons";
import backgroundImage from "../assets/a.jpeg"; 

function Home() {
  const [files, setFiles] = useState([]);
  const [uploadPercentage, setUploadPercentage] = useState(0);
  const [dragging, setDragging] = useState(false);
  const [uploading, setUploading] = useState(false);
  const [inputKey, setInputKey] = useState(0);
  const [drives, setDrives] = useState([]);
  const [selectedDrive, setSelectedDrive] = useState("");
  const [showOptions, setShowOptions] = useState(false);
  const [errorMessage, setErrorMessage] = useState("");
  const navigate = useNavigate();

  const detectDrives = () => {
    axios
      .get("http://127.0.0.1:8000/api/detect")
      .then((response) => {
        setDrives(response.data.drives);
        if (response.data.drives.length > 0) {
          setSelectedDrive(response.data.drives[0]);
        }
      })
      .catch((error) => console.error("Error fetching drives:", error));
  };

  const onChange = (e) => {
    const selectedFiles = Array.from(e.target.files);
    const fileMetadata = selectedFiles.map((file) => ({
      file,
      name: file.name,
      size: (file.size / 1024 / 1024).toFixed(2),
      type: file.type,
      lastModified: new Date(file.lastModified).toLocaleDateString(),
      extension: file.name.split(".").pop().toLowerCase(),
      icon:
        fileIcons[file.name.split(".").pop().toLowerCase()] ||
        fileIcons["default"],
    }));
    setFiles(fileMetadata);
    setUploading(false);
    startProgress();
  };

  const startProgress = () => {
    setUploading(true);
    let progress = 0;
    const interval = setInterval(() => {
      if (progress >= 100) {
        clearInterval(interval);
      } else {
        progress += 10; // Adjust speed of progress increment
        setUploadPercentage(progress);
      }
    }, 50); // Adjust the speed of the progress animation
  };

  const onDrop = (e) => {
    e.preventDefault();
    setDragging(false);

    const files = [];
    const items = e.dataTransfer.items;

    if (items && items.length > 0) {
      for (let i = 0; i < items.length; i++) {
        const item = items[i];
        if (item.kind === "file") {
          const entry = item.webkitGetAsEntry();
          if (entry) {
            if (entry.isDirectory) {
              // Handle directory
              const reader = entry.createReader();
              reader.readEntries((entries) => {
                entries.forEach((entry) => processEntry(entry, ""));
              });
            } else {
              // Handle single file
              item.file((file) => {
                files.push({
                  file,
                  name: file.name,
                  size: (file.size / 1024 / 1024).toFixed(2),
                  type: file.type,
                  lastModified: new Date(
                    file.lastModified
                  ).toLocaleDateString(),
                  extension: file.name.split(".").pop().toLowerCase(),
                  icon:
                    fileIcons[file.name.split(".").pop().toLowerCase()] ||
                    fileIcons["default"],
                });
                setFiles((prevFiles) => [...prevFiles, ...files]);
                startProgress();
              });
            }
          }
        }
      }
      setUploading(false);
    }
  };

  const processEntry = (entry, path) => {
    if (entry.isDirectory) {
      const reader = entry.createReader();
      reader.readEntries((entries) => {
        entries.forEach((subEntry) =>
          processEntry(subEntry, path + entry.name + "/")
        );
      });
    } else {
      entry.file((file) => {
        setFiles((prevFiles) => [
          ...prevFiles,
          {
            file,
            name: path + file.name,
            size: (file.size / 1024 / 1024).toFixed(2),
            type: file.type,
            lastModified: new Date(file.lastModified).toLocaleDateString(),
            icon:
              fileIcons[file.name.split(".").pop().toLowerCase()] ||
              fileIcons["default"],
          },
        ]);
        startProgress(); 
      });
    }
  };

  const onDragOver = (e) => {
    e.preventDefault();
    setDragging(true);
  };

  const onDragLeave = (e) => {
    e.preventDefault();
    setDragging(false);
  };

  const onSubmit = (e) => {
    e.preventDefault();
    if (files.length === 0) {
      setErrorMessage("Please select a folder to upload.");
      return;
    }

    // No need for form data here since we are passing the file list via state
    setUploading(true);

    // Navigate to the Rules page with the files included in the state
    navigate("/rules", { state: { files } });
  };

  const handleCancel = (index) => {
    setFiles((prevFiles) => {
      const updatedFiles = prevFiles.filter((_, i) => i !== index);
  
      // If there are no more files, reset the progress and uploading states
      if (updatedFiles.length === 0) {
        setUploading(false);
        setUploadPercentage(0);
      }
  
      return updatedFiles;
    });
  };

  const handleCancelAll = () => {
    setFiles([]); 
    setUploading(false);  // Stop the progress bar
    setUploadPercentage(0); // Reset the percentage to 0
  };

  return (
    <div className="container">
      <div className="drive-container">
        <h2 className="drive-label">Connect Drive</h2>
        <button className="detect-drive-button" onClick={detectDrives}>
          Detect
        </button>
        {drives.length > 0 && (
          <div className="drive-list">
            {/* Add drive selection here if needed */}
          </div>
        )}
      </div>

      <div
        className={`upload-box ${dragging ? "dragging" : ""}`}
        onDrop={onDrop}
        onDragOver={onDragOver}
        onDragLeave={onDragLeave}
      >
        <h2 className="header">Upload Folder</h2>
        <form onSubmit={onSubmit}>
          <div className="upload-area">
            <label htmlFor="file-upload" className="upload-label">
              <img src={uploadIcon} alt="Upload Icon" className="upload-icon" />
              <span className="upload-text">Drag & Drop Your Folder Here</span>
              <span className="upload-text choose-file">Choose Folder</span>
              <input
                id="file-upload"
                type="file"
                className="hidden"
                key={inputKey}
                onChange={onChange}
                webkitdirectory="true"
                multiple
              />
            </label>
          </div>
          {uploading && (
            <div className="progress-bar">
              <div
                className="progress-bar-inner"
                style={{ width: `${uploadPercentage}%` }}
              ></div>
              <p className="upload-percentage">{uploadPercentage}%</p>
            </div>
          )}
          <div className="buttons">
            <button
              type="button"
              className="cancel-button"
              onClick={handleCancelAll}// Clears all files
            >
              Cancel
            </button>
            <button
              type="submit"
              className="submit-button"
              disabled={files.length === 0}
            >
              Next
            </button>
          </div>
        </form>
      </div>

      {/* Metadata Container */}
      {files.length > 0 && (
        <div className="metadata-container">
          {files.map((fileData, index) => (
            <div key={index} className="file-info">
              <div className="file-details">
                <div className="file-desc">
                <img
                  src={fileData.icon}
                  alt="File Icon"
                  className="file-icon"
                />
                  <div className="file-name">{fileData.name}</div>  
        </div>
                <div
                  className="file-cancel"
                  onClick={() => handleCancel(index)}
                >
                  ✖
                </div>
              </div>
              <table className="file-metadata-table">
                <tbody>
                  <tr>
                    <td className="metadata-label">Name</td>
                    <td className="metadata-value">{fileData.name}</td>
                  </tr>
                  <tr>
                    <td className="metadata-label">Size</td>
                    <td className="metadata-value">{fileData.size} MB</td>
                  </tr>
                  <tr>
                    <td className="metadata-label">Type</td>
                    <td className="metadata-value">{fileData.type}</td>
                  </tr>
                  <tr>
                    <td className="metadata-label">Last Modified</td>
                    <td className="metadata-value">{fileData.lastModified}</td>
                  </tr>
                </tbody>
              </table>
            </div>
          ))}
        </div>
      )}
    </div>
  );
}

export default Home;
