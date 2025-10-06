import React, { useState, useEffect } from 'react';
import './App.css';
import text2CypherAPI from './api';

function App() {
  const [query, setQuery] = useState('');
  const [result, setResult] = useState(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState(null);
  const [queryHistory, setQueryHistory] = useState([]);
  const [showHistory, setShowHistory] = useState(false);
  const [copied, setCopied] = useState(false);
  const [chatAnswer, setChatAnswer] = useState(null);
  const [chatThread, setChatThread] = useState([]);

  // Working cybersecurity queries based on actual database structure
  const sampleQueries = [
    // Single Node Property Queries (Working)
    "Show all CVEs with HIGH severity",
    "Find CVEs with exploitability score greater than 8",
    "Show CVEs that require user interaction",
    "Find CWE weakness with ID CWE-1004",
    "Find CAPEC pattern with ID 1",
    "Show CWE weaknesses with Draft status",
    "Find CVEs with vector string containing 'AV:N'",
    "Show CAPEC patterns with High severity",
    "Find CPE entries for Microsoft products",
    "Find CVEs that can obtain all privileges",
    
    // Relationship-Based Queries (Working)
    "Find CAPEC patterns related to CWE-404",
    "Show CVEs that affect Microsoft Windows platforms",
    "Find groups using specific MITRE techniques",
    "Show software used by specific threat groups",
    "Find CVEs related to Adobe products"
  ];

  // Load query history from localStorage on component mount
  useEffect(() => {
    const savedHistory = localStorage.getItem('text2cypher_history');
    if (savedHistory) {
      setQueryHistory(JSON.parse(savedHistory));
    }
  }, []);

  // Save query history to localStorage whenever it changes
  useEffect(() => {
    localStorage.setItem('text2cypher_history', JSON.stringify(queryHistory));
  }, [queryHistory]);

  const handleSubmit = async (e) => {
    e.preventDefault();
    if (!query.trim()) return;

    setLoading(true);
    setError(null);
    setResult(null);
    setCopied(false);

    try {
      const response = await text2CypherAPI.query(query);
      setResult(response);
      
      // Add to query history
      const newHistoryItem = {
        id: Date.now(),
        query: query,
        cypher: response.cypher,
        timestamp: new Date().toISOString(),
        resultCount: Array.isArray(response.result) ? response.result.length : 1
      };
      
      setQueryHistory(prev => [newHistoryItem, ...prev.slice(0, 9)]); // Keep last 10 queries
      setChatAnswer(null);
    } catch (err) {
      setError(err.message || 'Failed to generate Cypher query');
    } finally {
      setLoading(false);
    }
  };

  const handleSampleQuery = (sampleQuery) => {
    setQuery(sampleQuery);
  };

  const handleHistoryItem = (historyItem) => {
    setQuery(historyItem.query);
    setResult({
      cypher: historyItem.cypher,
      result: [] // We don't store results in history to save space
    });
    setShowHistory(false);
  };

  const copyToClipboard = (text) => {
    navigator.clipboard.writeText(text);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  const clearHistory = () => {
    setQueryHistory([]);
    localStorage.removeItem('text2cypher_history');
  };

  const formatTimestamp = (timestamp) => {
    return new Date(timestamp).toLocaleString();
  };

  const askFromHistory = async () => {
    if (!query.trim()) return;
    try {
      setLoading(true);
      const { answer } = await text2CypherAPI.chatHistory('demo1', query);
      setChatAnswer(answer);
      setChatThread(prev => [...prev, { role: 'user', content: query }, { role: 'assistant', content: answer }]);
      setResult(null);
    } catch (err) {
      setError(err.message || 'Chat history failed');
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="App">
      <header className="App-header">
        <div className="header-content">
          <h1>Cybersecurity Text2Cypher Assistant</h1>
          <p>Transform natural language into Cypher queries for your cybersecurity knowledge graph</p>
        </div>

        <div className="main-container">
          <div className="query-section">
            <form onSubmit={handleSubmit} className="query-form">
              <div className="input-group">
                <input
                  type="text"
                  placeholder="Ask about vulnerabilities, weaknesses, attack patterns, threat groups... (e.g., Show all CVEs with HIGH severity)"
                  className="query-input"
                  value={query}
                  onChange={(e) => setQuery(e.target.value)}
                  disabled={loading}
                />
                <button 
                  type="submit" 
                  className="submit-button"
                  disabled={loading || !query.trim()}
                >
                  {loading ? 'Generating...' : 'Generate Cypher'}
                </button>
              </div>
            </form>

            <div className="action-buttons">
              <button 
                className="history-button"
                onClick={() => setShowHistory(!showHistory)}
              >
                {showHistory ? 'Hide' : 'Show'} History
              </button>
              <button 
                className="secondary-button"
                onClick={askFromHistory}
                disabled={loading || !query.trim()}
              >
                Ask from History
              </button>
              {queryHistory.length > 0 && (
                <button 
                  className="clear-button"
                  onClick={clearHistory}
                >
                  Clear History
                </button>
              )}
            </div>
          </div>

          {error && (
            <div className="error">
              <h3>Error:</h3>
              <p>{error}</p>
            </div>
          )}

          <div className="content-sections">
            {/* Sample Queries Section */}
            <div className="sample-queries">
              <h3>Try these cybersecurity queries:</h3>
              <div className="query-categories">
                <div className="category">
                  <h4>CVE Vulnerabilities</h4>
                  <div className="sample-grid">
                    {sampleQueries.slice(0, 3).map((sample, index) => (
                      <button
                        key={index}
                        className="sample-button cve"
                        onClick={() => handleSampleQuery(sample)}
                        disabled={loading}
                      >
                        {sample}
                      </button>
                    ))}
                  </div>
                </div>
                
                <div className="category">
                  <h4>CWE Weaknesses</h4>
                  <div className="sample-grid">
                    {sampleQueries.slice(3, 5).map((sample, index) => (
                      <button
                        key={index + 3}
                        className="sample-button cwe"
                        onClick={() => handleSampleQuery(sample)}
                        disabled={loading}
                      >
                        {sample}
                      </button>
                    ))}
                  </div>
                </div>
                
                <div className="category">
                  <h4>CAPEC Attack Patterns</h4>
                  <div className="sample-grid">
                    {sampleQueries.slice(5, 7).map((sample, index) => (
                      <button
                        key={index + 5}
                        className="sample-button capec"
                        onClick={() => handleSampleQuery(sample)}
                        disabled={loading}
                      >
                        {sample}
                      </button>
                    ))}
                  </div>
                </div>
                
                <div className="category">
                  <h4>Property Queries</h4>
                  <div className="sample-grid">
                    {sampleQueries.slice(7, 10).map((sample, index) => (
                      <button
                        key={index + 7}
                        className="sample-button property"
                        onClick={() => handleSampleQuery(sample)}
                        disabled={loading}
                      >
                        {sample}
                      </button>
                    ))}
                  </div>
                </div>
                
                <div className="category">
                  <h4>Relationship Queries</h4>
                  <div className="sample-grid">
                    {sampleQueries.slice(10, 15).map((sample, index) => (
                      <button
                        key={index + 10}
                        className="sample-button relationship"
                        onClick={() => handleSampleQuery(sample)}
                        disabled={loading}
                      >
                        {sample}
                      </button>
                    ))}
                  </div>
                </div>
              </div>
            </div>

            {/* Query History Section */}
            {showHistory && (
              <div className="history-section">
                <h3>Recent Queries:</h3>
                {queryHistory.length === 0 ? (
                  <p className="no-history">No query history yet. Start by asking a cybersecurity question!</p>
                ) : (
                  <div className="history-list">
                    {queryHistory.map((item) => (
                      <div key={item.id} className="history-item">
                        <div className="history-content">
                          <p className="history-query">{item.query}</p>
                          <p className="history-cypher">{item.cypher}</p>
                          <div className="history-meta">
                            <span className="history-time">{formatTimestamp(item.timestamp)}</span>
                            <span className="history-count">{item.resultCount} results</span>
                          </div>
                        </div>
                        <button
                          className="reuse-button"
                          onClick={() => handleHistoryItem(item)}
                        >
                          Reuse
                        </button>
                      </div>
                    ))}
                  </div>
                )}
              </div>
            )}

            {/* Results Section */}
            {result && (
              <div className="result">
                <div className="result-header">
                  <h2>Generated Cypher Query:</h2>
                  <button
                    className="copy-button"
                    onClick={() => copyToClipboard(result.cypher)}
                  >
                    {copied ? 'Copied!' : 'Copy Cypher'}
                  </button>
                </div>
                
                <pre className="cypher-query">{result.cypher}</pre>
                
                <div className="results-section">
                  <h3>Query Results:</h3>
                  <div className="results-container">
                    <pre className="query-results">
                      {JSON.stringify(result.result, null, 2)}
                    </pre>
                    <button
                      className="copy-button secondary"
                      onClick={() => copyToClipboard(JSON.stringify(result.result, null, 2))}
                    >
                      Copy Results
                    </button>
                  </div>
                </div>
              </div>
            )}
            {chatAnswer && (
              <div className="chat-answer">
                <h3>Answer from History:</h3>
                <p>{chatAnswer}</p>
              </div>
            )}
            {chatThread.length > 0 && (
              <div className="chat-thread">
                <h3>Chat History (demo1):</h3>
                {chatThread.map((m, idx) => (
                  <p key={idx} className={m.role === 'user' ? 'chat-user' : 'chat-assistant'}>
                    <strong>{m.role === 'user' ? 'You' : 'Assistant'}:</strong> {m.content}
                  </p>
                ))}
              </div>
            )}
          </div>
        </div>
      </header>
    </div>
  );
}

export default App;
