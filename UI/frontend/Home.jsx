import React from "react";
import { useNavigate } from "react-router-dom";

export default function Home() {
  const navigate = useNavigate();

  return (
    <div className="Home">
      {/* Hero Section */}
      <section className="hero-section">
        <div className="hero-content">
          <div className="hero-badge">
            <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
              <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/>
            </svg>
            <span>Unified Cybersecurity Knowledge Graph</span>
          </div>
          <h1 className="hero-title">
            Explore Cybersecurity<br/>
            <span className="hero-highlight">Intelligence</span> with AI
          </h1>
          <p className="hero-description">
            Query vulnerabilities, attack patterns, and security relationships through
            an intelligent knowledge graph powered by advanced RAG technology.
          </p>
          <div className="hero-actions">
            <button className="btn-primary" onClick={() => navigate('/qna')}>
              <span>Start Querying</span>
              <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                <path d="M5 12h14M12 5l7 7-7 7"/>
              </svg>
            </button>
            <button className="btn-secondary" onClick={() => navigate('/graph')}>
              <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                <circle cx="12" cy="12" r="3"/>
                <circle cx="5" cy="6" r="3"/>
                <circle cx="19" cy="6" r="3"/>
                <circle cx="5" cy="18" r="3"/>
                <circle cx="19" cy="18" r="3"/>
                <line x1="7.5" y1="7.5" x2="9.5" y2="10"/>
                <line x1="16.5" y1="7.5" x2="14.5" y2="10"/>
                <line x1="7.5" y1="16.5" x2="9.5" y2="14"/>
                <line x1="16.5" y1="16.5" x2="14.5" y2="14"/>
              </svg>
              <span>Explore Graph</span>
            </button>
          </div>
        </div>
        <div className="hero-visual">
          <div className="floating-card card-1">
            <div className="card-icon">
              <svg width="28" height="28" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/>
              </svg>
            </div>
            <div className="card-text">CVE Analysis</div>
          </div>
          <div className="floating-card card-2">
            <div className="card-icon">
              <svg width="28" height="28" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                <circle cx="11" cy="11" r="8"/>
                <path d="m21 21-4.35-4.35"/>
              </svg>
            </div>
            <div className="card-text">Threat Intelligence</div>
          </div>
          <div className="floating-card card-3">
            <div className="card-icon">
              <svg width="28" height="28" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                <polygon points="13 2 3 14 12 14 11 22 21 10 12 10 13 2"/>
              </svg>
            </div>
            <div className="card-text">RAG-Powered</div>
          </div>
        </div>
      </section>

      {/* Features Section */}
      <section className="features-section">
        <h2 className="section-title">Powerful Capabilities</h2>
        <div className="features-grid">
          <div className="feature-card">
            <div className="feature-icon">
              <svg width="32" height="32" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                <path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"/>
                <polyline points="7 10 12 15 17 10"/>
                <line x1="12" y1="15" x2="12" y2="3"/>
              </svg>
            </div>
            <h3>Natural Language Queries</h3>
            <p>Ask questions in plain English about vulnerabilities, weaknesses, and attack patterns.</p>
          </div>

          <div className="feature-card">
            <div className="feature-icon">
              <svg width="32" height="32" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                <circle cx="12" cy="12" r="10"/>
                <path d="M12 6v6l4 2"/>
              </svg>
            </div>
            <h3>Real-Time Visualization</h3>
            <p>Explore relationships between CVEs, CWEs, CPEs, and MITRE ATT&CK techniques visually.</p>
          </div>

          <div className="feature-card">
            <div className="feature-icon">
              <svg width="32" height="32" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                <path d="M22 12h-4l-3 9L9 3l-3 9H2"/>
              </svg>
            </div>
            <h3>AI-Powered Insights</h3>
            <p>Leverage RAG technology for contextual answers with source citations and confidence scores.</p>
          </div>

          <div className="feature-card">
            <div className="feature-icon">
              <svg width="32" height="32" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                <polygon points="12 2 2 7 12 12 22 7 12 2"/>
                <polyline points="2 17 12 22 22 17"/>
                <polyline points="2 12 12 17 22 12"/>
              </svg>
            </div>
            <h3>Multi-Source Integration</h3>
            <p>Unified access to CVE, CWE, CPE, CAPEC, MITRE ATT&CK, and D3FEND knowledge bases.</p>
          </div>
        </div>
      </section>

      {/* Data Sources Section */}
      <section className="sources-section">
        <h2 className="section-title">Integrated Data Sources</h2>
        <div className="sources-grid">
          <div className="source-badge">
            <div className="source-label">CVE</div>
            <div className="source-desc">Vulnerabilities</div>
          </div>
          <div className="source-badge">
            <div className="source-label">CWE</div>
            <div className="source-desc">Weaknesses</div>
          </div>
          <div className="source-badge">
            <div className="source-label">CPE</div>
            <div className="source-desc">Platforms</div>
          </div>
          <div className="source-badge">
            <div className="source-label">CAPEC</div>
            <div className="source-desc">Attack Patterns</div>
          </div>
          <div className="source-badge">
            <div className="source-label">MITRE ATT&CK</div>
            <div className="source-desc">Tactics & Techniques</div>
          </div>
          <div className="source-badge">
            <div className="source-label">D3FEND</div>
            <div className="source-desc">Defensive Countermeasures</div>
          </div>
        </div>
      </section>

      {/* CTA Section */}
      <section className="cta-section">
        <div className="cta-content">
          <h2>Ready to Explore?</h2>
          <p>Start querying the unified cybersecurity knowledge graph now</p>
          <button className="btn-cta" onClick={() => navigate('/qna')}>
            Launch Q&A Interface
            <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
              <path d="M5 12h14M12 5l7 7-7 7"/>
            </svg>
          </button>
        </div>
      </section>
    </div>
  );
} 