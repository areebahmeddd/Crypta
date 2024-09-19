import React from "react";
import "../styles/Team.css";
import areebImage from "../assets/team/areeb.png";
import shivanshImage from "../assets/team/shivansh.png";
import avantikaImage from "../assets/team/avantika.jpeg";
import yukthaImage from "../assets/team/yuktha.jpg";
import rishiImage from "../assets/team/rishi.jpg";
import shashwatImage from "../assets/team/shashwat.jpg";
import { FontAwesomeIcon } from "@fortawesome/react-fontawesome";
import { faGithub, faLinkedin } from "@fortawesome/free-brands-svg-icons";

const Team = () => {
  const teamMembers = [
    {
      name: "Areeb Ahmed",
      role: "Backend Developer",
      email: "areebshariff@acm.org",
      image: areebImage,
      github: "https://github.com/areebahmeddd",
      linkedin: "https://linkedin.com/in/areebahmeddd",
    },
    {
      name: "Shivansh Karan",
      role: "Backend Developer",
      email: "shivansh.karan@gmail.com",
      image: shivanshImage,
      github: "https://github.com/SpaceTesla",
      linkedin: "https://linkedin.com/in/shivansh-karan",
    },
    {
      name: "Avantika Kesarwani",
      role: "Backend Developer",
      email: "avikesar2013@gmail.com",
      image: avantikaImage,
      github: "https://github.com/avii09",
      linkedin: "https://linkedin.com/in/avantika-kesarwani",
    },
    {
      name: "Yuktha PS",
      role: "AI/ML Developer",
      email: "psyuktha@gmail.com",
      image: yukthaImage,
      github: "https://github.com/psyuktha",
      linkedin: "https://linkedin.com/in/yuktha-p-s",
    },
    {
      name: "Shashwat Kumar",
      role: "Web Developer",
      email: "shashwatkr8933@gmail.com",
      image: shashwatImage,
      github: "https://github.com/shashwat6204",
      linkedin: "https://linkedin.com/in/shashwatkumar",
    },
    {
      name: "Rishi Chirchi",
      role: "App Developer",
      email: "rishiraj.chirchi@gmail.com",
      image: rishiImage,
      github: "https://github.com/rishichirchi",
      linkedin: "https://linkedin.com/in/rishiraj-chirchi",
    },
  ];

  return (
    <div className="team-page">
      <div className="team-header-container">
        <div className="team-header">
          <h1>Meet the Crypta Team</h1>
          <p>
            We're a group of computer science undergraduate students united by a
            shared passion for open source and all things tech :)
          </p>
        </div>
      </div>

      <div className="team-grid">
        {teamMembers.slice(0, 6).map((member, index) => (
          <div className="team-card" key={index}>
            <img src={member.image} alt={member.name} className="team-photo" />
            <div className="team-info">
              <h3>{member.name}</h3>
              <h4>{member.role}</h4>
              <p className="team-email">
                <a href={`mailto:${member.email}`}>{member.email}</a>
              </p>
              <div className="team-links">
                <a
                  href={member.github}
                  className="btn github-btn"
                  target="_blank"
                  rel="noopener noreferrer"
                >
                  <FontAwesomeIcon icon={faGithub} /> GitHub
                </a>
                <a
                  href={member.linkedin}
                  className="btn linkedin-btn"
                  target="_blank"
                  rel="noopener noreferrer"
                >
                  <FontAwesomeIcon icon={faLinkedin} /> LinkedIn
                </a>
              </div>
            </div>
          </div>
        ))}
      </div>
    </div>
  );
};

export default Team;
