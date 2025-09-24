import React from "react";
import { BrowserRouter as Router, Routes, Route, NavLink } from "react-router-dom";
import Home from "./Home.jsx";
import Nvl from "./nvl.jsx";

export default function App() {
  return (
    <Router>
      {/* Create the <nav> and <a> in html */}
      <nav>
        <div  className='logo'>
          <img src="https://www.angelo.edu/live/resource/image/_i/themes/global/assets/images/asu-logo-white-gold.rev.1600281398.svg" alt="ASU" />
        </div>
        <NavLink to="/" className={({ isActive }) => isActive ? 'active' : ''}>Home</NavLink>
        {/* <NavLink to="/qna" className={({ isActive }) => isActive ? 'active' : ''}>Q&A</NavLink> */}
        <NavLink to="/graph" className={({ isActive }) => isActive ? 'active' : ''}>Q&A</NavLink>
      </nav>
      {/* Set the link path of <a> */}
      <Routes>
        <Route path="/" element={<Home />} />
        {/* <Route path="/qna" element={<QnAPage />} /> */}
        <Route path="/graph" element={<Nvl />} />
      </Routes>
    </Router>
  );
}