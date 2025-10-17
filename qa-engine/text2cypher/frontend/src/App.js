import React, { useState, useEffect } from 'react';
import './App.css';
import text2CypherAPI from './api';
import sampleQueriesData from './sampleQueries.json';

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
  
  // V4 Demo Features
  const [showSchema, setShowSchema] = useState(false);
  const [schemaInfo, setSchemaInfo] = useState(null);
  const [validationInfo, setValidationInfo] = useState(null);
  const [showV4Features, setShowV4Features] = useState(false);
  const [activeTab, setActiveTab] = useState('query');
  
  // Pagination for large result sets
  const [currentPage, setCurrentPage] = useState(1);
  const [itemsPerPage] = useState(50); // Show only 50 items at a time

  // Pagination functions
  const getPaginatedResults = (results) => {
    if (!Array.isArray(results)) return [];
    const startIndex = (currentPage - 1) * itemsPerPage;
    const endIndex = startIndex + itemsPerPage;
    return results.slice(startIndex, endIndex);
  };

  const getTotalPages = (results) => {
    if (!Array.isArray(results)) return 0;
    return Math.ceil(results.length / itemsPerPage);
  };

  const handlePageChange = (page) => {
    setCurrentPage(page);
  };

  // Categorized sample queries aligned with the current schema
  const categorizedSamples = sampleQueriesData;

  // Load query history from localStorage on component mount
  useEffect(() => {
    const savedHistory = localStorage.getItem('text2cypher_history');
    if (savedHistory) {
      setQueryHistory(JSON.parse(savedHistory));
    }
    
    // Load V4 system information
    loadV4SystemInfo();
  }, []);

  // V4 System Information Loading
  const loadV4SystemInfo = async () => {
    try {
      const [schemaResponse, validationResponse] = await Promise.all([
        text2CypherAPI.getSchema(),
        text2CypherAPI.getValidationInfo()
      ]);
      setSchemaInfo(schemaResponse);
      setValidationInfo(validationResponse);
    } catch (error) {
      console.error('Failed to load V4 system info:', error);
    }
  };

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
    setCurrentPage(1); // Reset to first page

    try {
      const response = await text2CypherAPI.query(query);
      
      // V4 Response Format Handling
      if (response.status === 'error') {
        setError(response.message || 'Query failed');
        setResult({
          cypher: null,
          result: [],
          status: response.status,
          message: response.message,
          suggestions: response.suggestions || []
        });
      } else {
        setResult(response);
      }
      
      // Add to query history
      const newHistoryItem = {
        id: Date.now(),
        query: query,
        cypher: response.cypher,
        timestamp: new Date().toISOString(),
        resultCount: Array.isArray(response.result) ? response.result.length : 0,
        status: response.status || 'success'
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
          <h1>Cybersecurity Text2Cypher V4 Assistant</h1>
          <p>Enterprise-grade natural language to Cypher conversion with intelligent error handling and advanced validation</p>
          
          {/* V4 Feature Badges */}
          <div className="v4-features">
            <span className="feature-badge">✅ Advanced Queries</span>
            <span className="feature-badge">✅ Smart Error Handling</span>
            <span className="feature-badge">✅ Cypher Guard Validation</span>
          </div>
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
              <button 
                className="v4-button"
                onClick={() => setShowV4Features(!showV4Features)}
              >
                {showV4Features ? 'Hide' : 'Show'} V4 Features
              </button>
              <button 
                className="schema-button"
                onClick={() => setShowSchema(!showSchema)}
              >
                {showSchema ? 'Hide' : 'Show'} Schema
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
            {/* V4 Features Demo Section */}
            {showV4Features && (
              <div className="v4-features-section">
                <h3>🚀 Text2Cypher V4 Features Demo</h3>
                <div className="v4-tabs">
                  <button 
                    className={`tab-button ${activeTab === 'query' ? 'active' : ''}`}
                    onClick={() => setActiveTab('query')}
                  >
                    Query Examples
                  </button>
                  <button 
                    className={`tab-button ${activeTab === 'schema' ? 'active' : ''}`}
                    onClick={() => setActiveTab('schema')}
                  >
                    Schema Info
                  </button>
                  <button 
                    className={`tab-button ${activeTab === 'validation' ? 'active' : ''}`}
                    onClick={() => setActiveTab('validation')}
                  >
                    Validation System
                  </button>
                  <button 
                    className={`tab-button ${activeTab === 'errors' ? 'active' : ''}`}
                    onClick={() => setActiveTab('errors')}
                  >
                    Error Handling
                  </button>
                </div>

                {activeTab === 'query' && (
                  <div className="v4-content">
                    <h4>Schema-valid Query Categories</h4>
                    <div className="query-categories">
                      {Object.entries(categorizedSamples).map(([category, queries]) => (
                        <div className="category" key={category}>
                          <h5>{category}</h5>
                          <div className="sample-grid">
                            {queries.map((sample, index) => (
                              <button
                                key={category + index}
                                className="sample-button"
                                onClick={() => handleSampleQuery(sample)}
                                disabled={loading}
                              >
                                {sample}
                              </button>
                            ))}
                          </div>
                        </div>
                      ))}
                    </div>
                  </div>
                )}

                {activeTab === 'schema' && schemaInfo && (
                  <div className="v4-content">
                    <h4>V4 Schema Information</h4>
                    <div className="schema-info">
                      <div className="schema-stats">
                        <div className="stat">
                          <strong>Node Types:</strong> {Array.isArray(schemaInfo.node_types) ? schemaInfo.node_types.length : 'Loading...'}
                        </div>
                        <div className="stat">
                          <strong>Relationship Types:</strong> {Array.isArray(schemaInfo.relationship_types) ? schemaInfo.relationship_types.length : 'Loading...'}
                        </div>
                        <div className="stat">
                          <strong>Schema Status:</strong> {schemaInfo.schema_status || '❌ Not Loaded'}
                        </div>
                      </div>
                      
                      {Array.isArray(schemaInfo.node_types) && schemaInfo.node_types.length > 0 && (
                        <div className="node-types-info">
                          <h5>Available Node Types:</h5>
                          <div className="node-types-list">
                            {schemaInfo.node_types.map((nodeType, index) => (
                              <span key={index} className="node-type-tag">{nodeType}</span>
                            ))}
                          </div>
                        </div>
                      )}
                      
                      {Array.isArray(schemaInfo.relationship_types) && schemaInfo.relationship_types.length > 0 && (
                        <div className="relationship-types-info">
                          <h5>Available Relationship Types:</h5>
                          <div className="relationship-types-list">
                            {schemaInfo.relationship_types.map((relType, index) => (
                              <span key={index} className="relationship-type-tag">{relType}</span>
                            ))}
                          </div>
                        </div>
                      )}
                      
                      {result && result.relationship_info && (
                        <div className="query-relationships-info">
                          <h5>🔗 Relationships Used in Current Query:</h5>
                          <div className="query-relationships">
                            <div className="relationship-section">
                              <strong>Node Types:</strong> {result.relationship_info.used_node_types.join(', ') || 'None'}
                            </div>
                            <div className="relationship-section">
                              <strong>Relationship Types:</strong> {result.relationship_info.used_relationships.join(', ') || 'None'}
                            </div>
                            <div className="relationship-section">
                              <strong>Query Patterns:</strong> {result.relationship_info.query_patterns.join(', ') || 'None'}
                            </div>
                          </div>
                        </div>
                      )}
                      
                      {schemaInfo.bidirectional_connections && (
                        <div className="bidirectional-info">
                          <h5>Bidirectional Connections:</h5>
                          <pre className="schema-preview">
                            {JSON.stringify(schemaInfo.bidirectional_connections, null, 2).substring(0, 500)}...
                          </pre>
                        </div>
                      )}
                    </div>
                  </div>
                )}

                {activeTab === 'validation' && validationInfo && (
                  <div className="v4-content">
                    <h4>V4 Validation System</h4>
                    <div className="validation-info">
                      <div className="validation-stats">
                        <div className="stat">
                          <strong>Validation Mode:</strong> {validationInfo.validation_mode || 'Unknown'}
                        </div>
                        <div className="stat">
                          <strong>Node Types Validated:</strong> {validationInfo.node_types || 'Unknown'}
                        </div>
                        <div className="stat">
                          <strong>Relationship Types:</strong> {validationInfo.relationship_types || 'Unknown'}
                        </div>
                        <div className="stat">
                          <strong>Schema Loaded:</strong> {validationInfo.schema_loaded ? '✅ Yes' : '❌ No'}
                        </div>
                      </div>
                      {validationInfo.features && (
                        <div className="validation-features">
                          <h5>Validation Features:</h5>
                          <ul>
                            {validationInfo.features.map((feature, index) => (
                              <li key={index}>✅ {feature}</li>
                            ))}
                          </ul>
                        </div>
                      )}
                    </div>
                  </div>
                )}

                {activeTab === 'errors' && (
                  <div className="v4-content">
                    <h4>V4 Intelligent Error Handling</h4>
                    <div className="error-demo">
                      <p>Try these queries to see V4's intelligent error handling:</p>
                      <div className="error-examples">
                        <button 
                          className="error-demo-button"
                          onClick={() => handleSampleQuery("Find non-existent data")}
                        >
                          Test Empty Results Handling
                        </button>
                        <button 
                          className="error-demo-button"
                          onClick={() => handleSampleQuery("Show invalid query example")}
                        >
                          Test Query Validation
                        </button>
                        <button 
                          className="error-demo-button"
                          onClick={() => handleSampleQuery("Find CVEs from future year 2030")}
                        >
                          Test Data Not Found
                        </button>
                      </div>
                      <div className="error-features">
                        <h5>V4 Error Handling Features:</h5>
                        <ul>
                          <li>✅ LLM-generated helpful error messages</li>
                          <li>✅ Context-aware query suggestions</li>
                          <li>✅ Graceful error recovery</li>
                          <li>✅ User-friendly explanations</li>
                          <li>✅ Smart alternative suggestions</li>
                        </ul>
                      </div>
                    </div>
                  </div>
                )}
              </div>
            )}

            {/* Sample Queries Section (categorized) */}
            <div className="sample-queries">
              <h3>Try schema-valid query examples by category:</h3>
              <div className="query-categories">
                {Object.entries(categorizedSamples).map(([category, queries]) => (
                  <div className="category" key={category}>
                    <h4>{category}</h4>
                    <div className="sample-grid">
                      {queries.map((sample, index) => (
                        <button
                          key={category + index}
                          className="sample-button"
                          onClick={() => handleSampleQuery(sample)}
                          disabled={loading}
                        >
                          {sample}
                        </button>
                      ))}
                    </div>
                  </div>
                ))}
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
                  <h2>V4 Response:</h2>
                  <div className="result-status">
                    <span className={`status-badge ${result.status || 'success'}`}>
                      {result.status === 'error' ? '❌ Error' : 
                       result.status === 'no_results' ? '⚠️ No Results' : 
                       '✅ Success'}
                    </span>
                    {result.count !== undefined && (
                      <span className="result-count">{result.count} results</span>
                    )}
                  </div>
                </div>

                {result.message && (
                  <div className={`result-message ${result.status || 'success'}`}>
                    <p>{result.message}</p>
                  </div>
                )}

                {result.cypher && (
                  <div className="cypher-section">
                    <h3>Generated Cypher Query:</h3>
                    <div className="cypher-container">
                      <pre className="cypher-query">{result.cypher}</pre>
                      <button
                        className="copy-button"
                        onClick={() => copyToClipboard(result.cypher)}
                      >
                        {copied ? 'Copied!' : 'Copy Cypher'}
                      </button>
                    </div>
                  </div>
                )}

                {result.result && result.result.length > 0 && (
                  <div className="results-section">
                    <h3>Query Results ({result.count || result.result.length} total):</h3>
                    <div className="results-container">
                      <div className="pagination-info">
                        Showing {((currentPage - 1) * itemsPerPage) + 1} to {Math.min(currentPage * itemsPerPage, result.result.length)} of {result.result.length} results
                      </div>
                      <pre className="query-results">
                        {JSON.stringify(getPaginatedResults(result.result), null, 2)}
                      </pre>
                      <button
                        className="copy-button secondary"
                        onClick={() => copyToClipboard(JSON.stringify(getPaginatedResults(result.result), null, 2))}
                      >
                        Copy Current Page
                      </button>
                      
                      {/* Pagination Controls */}
                      {getTotalPages(result.result) > 1 && (
                        <div className="pagination-controls">
                          <button
                            onClick={() => handlePageChange(currentPage - 1)}
                            disabled={currentPage === 1}
                            className="pagination-button"
                          >
                            Previous
                          </button>
                          <span className="pagination-info">
                            Page {currentPage} of {getTotalPages(result.result)}
                          </span>
                          <button
                            onClick={() => handlePageChange(currentPage + 1)}
                            disabled={currentPage === getTotalPages(result.result)}
                            className="pagination-button"
                          >
                            Next
                          </button>
                        </div>
                      )}
                    </div>
                  </div>
                )}

                {result.suggestions && result.suggestions.length > 0 && (
                  <div className="suggestions-section">
                    <h3>💡 V4 Smart Suggestions:</h3>
                    <ul className="suggestions-list">
                      {result.suggestions.map((suggestion, index) => (
                        <li key={index} className="suggestion-item">
                          <button
                            className="suggestion-button"
                            onClick={() => handleSampleQuery(suggestion.replace('Try: ', ''))}
                          >
                            {suggestion}
                          </button>
                        </li>
                      ))}
                    </ul>
                  </div>
                )}

                {result.error && (
                  <div className="error-details">
                    <h3>Error Details:</h3>
                    <pre className="error-text">{result.error}</pre>
                  </div>
                )}
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
