import React, { useState } from "react";
import { useNavigate } from "react-router-dom";
import axios from "axios";
import "../styles/Home.css";
import uploadIcon from "../assets/upload.png";
import fileIcons from "../assets/fileIcons";

function Home() {
  const navigate = useNavigate();
  const [files, setFiles] = useState([]);
  const [uploadPercentage, setUploadPercentage] = useState(0);
  const [dragging, setDragging] = useState(false);
  const [uploading, setUploading] = useState(false);
  const [inputKey, setInputKey] = useState(0);
  const [errorMessage, setErrorMessage] = useState("");

  // Detect connected drives and fetch files from the backend
  const detectDrives = async () => {
    try {
      const postResponse = await axios.post("https://crypta-bwgaebf7acgrdufv.southindia-01.azurewebsites.net/api/detect");
      console.log(postResponse.data);
      const getResponse = await axios.get("https://crypta-bwgaebf7acgrdufv.southindia-01.azurewebsites.net/api/files");
      console.log("File Metadata:", getResponse.data);

      if (getResponse.data.length > 0) {
        const filePromises = getResponse.data.map(async (file) => {
          const fileResponse = await axios.get(
            `https://crypta-bwgaebf7acgrdufv.southindia-01.azurewebsites.net/api/files/${file.name}`,
            { responseType: "blob" }
          );
          const fileBlob = new Blob([fileResponse.data]);
          const fileObject = new File([fileBlob], file.name, {
            type: file.type,
            lastModified: file.lastModified,
          });

          return {
            file: fileObject,
            name: file.name,
            size: (file.size / 1024 / 1024).toFixed(2),
            type: file.type || "Unknown",
            lastModified: new Date(file.lastModified).toLocaleDateString(),
            icon:
              fileIcons[file.name.split(".").pop().toLowerCase()] ||
              fileIcons["default"],
          };
        });

        const fileMetadata = await Promise.all(filePromises);
        setFiles(fileMetadata);
      }
    } catch (error) {
      setErrorMessage("Failed to detect drives or fetch files.");
    }
  };

  // Handle file selection through the input or drag-and-drop
  const onChange = (e) => {
    const selectedFiles = Array.from(e.target.files);
    const fileMetadata = selectedFiles.map((file) => ({
      file,
      name: file.name,
      size: (file.size / 1024 / 1024).toFixed(2),
      type: file.type || "Unknown",
      lastModified: new Date(file.lastModified).toLocaleDateString(),
      icon:
        fileIcons[file.name.split(".").pop().toLowerCase()] ||
        fileIcons["default"],
    }));
    setFiles(fileMetadata);
    setUploading(false);
    startProgress();
  };

  // Simulate progress bar animation
  const startProgress = () => {
    setUploading(true);
    let progress = 0;
    const interval = setInterval(() => {
      if (progress >= 100) {
        clearInterval(interval);
      } else {
        progress += 10;
        setUploadPercentage(progress);
      }
    }, 50); // Adjust progress animation speed here
  };

  // Handle file or folder drop into the upload area
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
              const reader = entry.createReader();
              reader.readEntries((entries) => {
                entries.forEach((entry) => processEntry(entry, ""));
              });
            } else {
              item.file((file) => {
                files.push({
                  file,
                  name: file.name,
                  size: (file.size / 1024 / 1024).toFixed(2),
                  type: file.type || "Unknown",
                  lastModified: new Date(file.lastModified).toLocaleDateString(),
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

  // Process each file or folder recursively if it's a directory
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
            type: file.type || "Unknown",
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

  // Set the dragging state when a file or folder is dragged over the upload area
  const onDragOver = (e) => {
    e.preventDefault();
    setDragging(true);
  };

  // Reset dragging state when the dragged file or folder leaves the upload area
  const onDragLeave = (e) => {
    e.preventDefault();
    setDragging(false);
  };

  // Handle form submission to move to the next step (e.g., rules page)
  const onSubmit = (e) => {
    e.preventDefault();
    if (files.length === 0) {
      setErrorMessage("Please select a folder to upload.");
      return;
    }
    setUploading(true);
    navigate("/rules", { state: { files } });
  };

  // Cancel individual file selection
  const handleCancel = (index) => {
    setFiles((prevFiles) => {
      const updatedFiles = prevFiles.filter((_, i) => i !== index);
      if (updatedFiles.length === 0) {
        setUploading(false);
        setUploadPercentage(0);
      }
      return updatedFiles;
    });
  };

  // Cancel all selected files and reset the state
  const handleCancelAll = () => {
    setFiles([]);
    setUploading(false);
    setUploadPercentage(0);
  };

  return (
    <div className="container">
      <div className="drive-container">
        <h2 className="drive-label">Connect Drive</h2>
        <button className="detect-drive-button" onClick={detectDrives}>
          Detect
        </button>
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
              <span className="upload-text">Drag & Drop Your Folder</span>
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
              onClick={handleCancelAll}
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
