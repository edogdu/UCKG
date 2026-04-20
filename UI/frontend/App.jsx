import React from "react";
import { BrowserRouter as Router, Routes, Route, NavLink } from "react-router-dom";
import Home from "./Home.jsx";
import Nvl from "./nvl.jsx";
import DualPanelLayout from "./DualPanelLayout.jsx";

export default function App() {
  return (
    <Router>
      {/* Create the <nav> and <a> in html */}
      <nav>
        <div  className='logo'>
          <img src="https://www.angelo.edu/live/resource/image/_i/themes/global/assets/images/asu-logo-white-gold.rev.1600281398.svg" alt="ASU" />
        </div>
        <NavLink to="/" className={({ isActive }) => isActive ? 'active' : ''}>Home</NavLink>
        <NavLink to="/qna" className={({ isActive }) => isActive ? 'active' : ''}>Q&A Chat</NavLink>
        <NavLink to="/graph" className={({ isActive }) => isActive ? 'active' : ''}>Graph Explorer</NavLink>


        <div class="hamburger" onClick={dropdown}>
          ☰
        </div>
        <div class='dropdown' id = 'drop'>
        <NavLink to="/" className={({ isActive }) => isActive ? 'active' : ''}>Home</NavLink>
        <NavLink to="/qna" className={({ isActive }) => isActive ? 'active' : ''}>Q&A Chat</NavLink>
        <NavLink to="/graph" className={({ isActive }) => isActive ? 'active' : ''}>Graph Explorer</NavLink>
        </div>
      </nav>


      {/* Set the link path of <a> */}
      <Routes>
        <Route path="/" element={<Home />} />
        <Route path="/qna" element={<DualPanelLayout />} />
        <Route path="/chat/qna" element={<DualPanelLayout />} />
        <Route path="/chat/interactive" element={<DualPanelLayout />} />
        <Route path="/graph" element={<Nvl />} />
      </Routes>
    </Router>
  );
}

function dropdown() {
  let x = document.getElementById('drop');
  if (x.style.display === 'block') {
    x.style.display = 'none';
  } else {
    x.style.display = 'block';
  }
}