import React from "react";
import { createRoot } from "react-dom/client";
import App from "./App.jsx";
import * as css from "./styles.css";

// Polyfill process for browser
import process from 'process';
window.process = process;

createRoot(document.getElementById("app")).render(
  <React.StrictMode>
    <App />
  </React.StrictMode>
);