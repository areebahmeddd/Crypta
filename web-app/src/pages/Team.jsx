// src/Team.js
import React from 'react';
import '../styles/Team.css';

// Importing images
import areebImage from '../assets/profile/areeb.png';
import shivanshImage from '../assets/profile/shivansh.png';
import avantikaImage from '../assets/profile/avantika.jpeg';
import yukthaImage from '../assets/profile/yuktha.jpg';
import rishiImage from '../assets/profile/rishi.jpg';
import shashwatImage from '../assets/profile/shashwat.jpg';

// Importing FontAwesome icons
import { FontAwesomeIcon } from '@fortawesome/react-fontawesome';
import { faGithub, faLinkedin } from '@fortawesome/free-brands-svg-icons';

const Team = () => {
  const teamMembers = [
    {
      name: 'Areeb Ahmed',
      role: 'Backend Developer',
      email: 'areebshariff@acm.org',
      image: areebImage,
      github: 'https://github.com/areebahmeddd',
      linkedin: 'https://www.linkedin.com/in/areebahmeddd'
    },
    {
      name: 'Shivansh Karan',
      role: 'Backend Developer',
      email: 'shivansh.karan@gmail.com',
      image: shivanshImage,
      github: 'https://github.com/SpaceTesla',
      linkedin: 'https://www.linkedin.com/in/shivansh-karan/'
    },
    {
      name: 'Avantika Kesarwani',
      role: 'Backend Developer',
      email: 'avikesar2013@gmail.com',
      image: avantikaImage,
      github: 'https://github.com/avii09',
      linkedin: 'https://www.linkedin.com/in/avantika-kesarwani/'
    },
    {
      name: 'PS Yuktha',
      role: 'Machine Learning Specialist',
      email: 'psyuktha@gmail.com',
      image: yukthaImage,
      github: 'https://github.com/psyuktha/',
      linkedin: 'https://www.linkedin.com/in/yuktha-p-s/'
    },
    {
      name: 'Rishi Chirchi',
      role: 'Application Developer',
      email: 'rishiraj.chirchi@gmail.com',
      image: rishiImage,
      github: 'https://github.com/rishichirchi',
      linkedin: 'https://www.linkedin.com/in/rishiraj-chirchi/'
    },
    {
      name: 'Shashwat Kumar',
      role: 'Web Developer',
      email: '1ds22cs199@dsce.edu.in',
      image: shashwatImage,
      github: 'https://github.com/shashwat6204',
      linkedin: 'https://www.linkedin.com/in/shashwatkumar-/'
    }
  ];

  
  return (
    <div className="team-page">
      <div className="team-header">
        <h1>Meet the Crypta Team</h1>
        <p>Our skilled and diverse team is committed to building secure, user-friendly solutions for your file vulnerability needs.</p>
      </div>

      <div className="team-grid">
        {teamMembers.slice(0, 4).map((member, index) => (
          <div className="team-card" key={index}>
            <img src={member.image} alt={member.name} className="team-photo" />
            <div className="team-info">
              <h3>{member.name}</h3>
              <h4>{member.role}</h4>
              <p className="team-email">
                <a href={`mailto:${member.email}`}>{member.email}</a>
              </p>
              <div className="team-links">
                <a href={member.github} className="btn github-btn" target="_blank" rel="noopener noreferrer">
                  <FontAwesomeIcon icon={faGithub} /> GitHub
                </a>
                <a href={member.linkedin} className="btn linkedin-btn" target="_blank" rel="noopener noreferrer">
                  <FontAwesomeIcon icon={faLinkedin} /> LinkedIn
                </a>
              </div>
            </div>
          </div>
        ))}
      </div>

      <div className="team-bottom-row">
        {teamMembers.slice(4).map((member, index) => (
          <div className="team-card" key={index}>
            <img src={member.image} alt={member.name} className="team-photo" />
            <div className="team-info">
              <h3>{member.name}</h3>
              <h4>{member.role}</h4>
              <p className="team-email">
                <a href={`mailto:${member.email}`}>{member.email}</a>
              </p>
              <div className="team-links">
                <a href={member.github} className="btn github-btn" target="_blank" rel="noopener noreferrer">
                  <FontAwesomeIcon icon={faGithub} /> GitHub
                </a>
                <a href={member.linkedin} className="btn linkedin-btn" target="_blank" rel="noopener noreferrer">
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