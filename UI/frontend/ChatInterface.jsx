import React, { useState, useRef, useEffect } from 'react';
import { executeRAGQuery, executeText2Cypher } from './connection';
import Markdown from 'react-markdown';

export default function ChatInterface({ onGraphUpdate, onModeChange }) {
  const [messages, setMessages] = useState([
    {
      type: 'assistant',
      text: 'Hello! I can help you explore the cybersecurity knowledge graph. Ask me about vulnerabilities, attack patterns, or relationships between security concepts.',
      timestamp: Date.now()
    }
  ]);
  const [inputValue, setInputValue] = useState('');
  const [isLoading, setIsLoading] = useState(false);
  const [queryMode, setQueryMode] = useState('rag'); // 'rag' or 'text2cypher'
  const chatContainerRef = useRef();
  const inputRef = useRef();

  // Auto-scroll to bottom when messages change
  useEffect(() => {
    if (chatContainerRef.current) {
      chatContainerRef.current.scrollTop = chatContainerRef.current.scrollHeight;
    }
  }, [messages]);

  const handleSendMessage = async () => {
    if (!inputValue.trim()) return;

    const userMessage = {
      type: 'user',
      text: inputValue,
      timestamp: Date.now()
    };

    setMessages(prev => [...prev, userMessage]);
    setIsLoading(true);

    try {
      let result;

      if (queryMode === 'rag') {
        // Use RAG query
        result = await executeRAGQuery(inputValue, 'auto');

        // Update graph with visualization data
        if (result.visualization_data && onGraphUpdate) {
          onGraphUpdate(result.visualization_data, 'rag');
        }

        // Create assistant response
        const assistantMessage = {
          type: 'assistant',
          text: result.answer,
          sources: result.chat_data?.sources || [],
          confidence: result.chat_data?.confidence || 0,
          mode: result.metadata?.mode || 'unknown',
          timestamp: Date.now(),
          metadata: result.metadata
        };

        setMessages(prev => [...prev, assistantMessage]);

      } else if (queryMode === 'text2cypher') {
        // Use Text2Cypher query (LangChain pattern)
        result = await executeText2Cypher(inputValue);

        console.log('Text2Cypher result:', result);
        console.log('Graph data:', result.graph_data);
        console.log('Nodes:', result.graph_data?.nodes?.length || 0);
        console.log('Relationships:', result.graph_data?.relationships?.length || 0);

        // Update graph with visualization data from Python backend
        if (result.graph_data && result.graph_data.nodes && result.graph_data.nodes.length > 0 && onGraphUpdate) {
          console.log('✓ Calling onGraphUpdate with:', result.graph_data);
          console.log('  - Nodes:', result.graph_data.nodes.length);
          console.log('  - Relationships:', result.graph_data.relationships.length);
          onGraphUpdate(result.graph_data, 'cypher');
        } else {
          if (!result.graph_data) {
            console.warn('⚠ No graph_data in result');
          } else if (!result.graph_data.nodes || result.graph_data.nodes.length === 0) {
            console.warn('⚠ No nodes in graph_data - query returned non-graph results');
          } else if (!onGraphUpdate) {
            console.warn('⚠ No onGraphUpdate callback');
          }
        }

        // Create assistant response with LLM-generated answer
        const assistantMessage = {
          type: 'assistant',
          text: result.answer,  // LLM-generated natural language response
          cypherQuery: result.cypher_query,  // Available for debugging
          confidence: result.confidence || 0,
          timestamp: Date.now(),
          hasGraphData: result.graph_data && result.graph_data.nodes && result.graph_data.nodes.length > 0
        };

        setMessages(prev => [...prev, assistantMessage]);
      }

    } catch (error) {
      console.error('Query failed:', error);
      const errorMessage = {
        type: 'assistant',
        text: `Sorry, I encountered an error: ${error.message}`,
        isError: true,
        timestamp: Date.now()
      };
      setMessages(prev => [...prev, errorMessage]);
    }

    setInputValue('');
    setIsLoading(false);

    // Focus back to input
    setTimeout(() => inputRef.current?.focus(), 100);
  };

  const handleKeyPress = (e) => {
    if (e.key === 'Enter' && !e.shiftKey) {
      e.preventDefault();
      handleSendMessage();
    }
  };

  const handleModeChange = (newMode) => {
    setQueryMode(newMode);
    if (onModeChange) {
      onModeChange(newMode);
    }
  };

  const formatSources = (sources) => {
    if (!sources || sources.length === 0) return null;

    return (
      <div className="message-sources">
        <div className="sources-header">Sources</div>
        <div className="sources-list">
          {sources.map((source, index) => (
            <div key={index} className="source-chip">
              <span className="source-label">{source.label}</span>
              <span className="source-score">{source.score}</span>
            </div>
          ))}
        </div>
      </div>
    );
  };

  const handleResetChat = () => {
    setMessages([
      {
        type: 'assistant',
        text: 'Hello! I can help you explore the cybersecurity knowledge graph. Ask me about vulnerabilities, attack patterns, or relationships between security concepts.',
        timestamp: Date.now()
      }
    ]);
    setInputValue('');
  };

  return (
    <div className="chat-interface">
      {/* Query Mode Selector */}
      <div className="query-mode-selector">
        <div className="mode-buttons-group">
          <button
            className={`mode-btn ${queryMode === 'rag' ? 'active' : ''}`}
            onClick={() => handleModeChange('rag')}
            title="Use GraphRAG (Graph Retrieval Augmented Generation) for contextual answers"
          >
            GraphRAG Mode
          </button>
          <button
            className={`mode-btn ${queryMode === 'text2cypher' ? 'active' : ''}`}
            onClick={() => handleModeChange('text2cypher')}
            title="Convert natural language to Cypher queries"
          >
            Text2Cypher Mode
          </button>
        </div>
        <button
          className="reset-chat-btn"
          onClick={handleResetChat}
          title="Reset conversation"
        >
          <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
            <path d="M3 12a9 9 0 0 1 9-9 9.75 9.75 0 0 1 6.74 2.74L21 8"/>
            <path d="M21 3v5h-5"/>
            <path d="M21 12a9 9 0 0 1-9 9 9.75 9.75 0 0 1-6.74-2.74L3 16"/>
            <path d="M3 21v-5h5"/>
          </svg>
          Reset Chat
        </button>
      </div>

      {/* Messages Container */}
      <div className="messages-container" ref={chatContainerRef}>
        {messages.map((message, index) => (
          <div key={index} className={`message ${message.type}`}>
            <div className="message-content">
              <Markdown>{message.text}</Markdown>

              {/* Show confidence if available */}
              {message.confidence && (
                <div className="message-confidence">
                  Confidence: {(message.confidence * 100).toFixed(1)}%
                </div>
              )}

              {/* Show mode if available */}
              {message.mode && (
                <div className="message-mode">
                  Mode: {message.mode}
                </div>
              )}

              {/* Show sources for RAG responses */}
              {formatSources(message.sources)}

              {/* Show execution results for Cypher queries */}
              {message.executionResult && (
                <div className="execution-result">
                  <h5>Query Results:</h5>
                  <div className="result-summary">
                    {message.executionResult.summary?.total_nodes || 0} nodes,
                    {message.executionResult.summary?.total_relationships || 0} relationships
                  </div>
                </div>
              )}
            </div>

            <div className="message-timestamp">
              {new Date(message.timestamp).toLocaleTimeString()}
            </div>
          </div>
        ))}

        {isLoading && (
          <div className="message assistant loading">
            <div className="message-content">
              <div className="typing-indicator">
                <span></span>
                <span></span>
                <span></span>
              </div>
              Processing your query...
            </div>
          </div>
        )}
      </div>

      {/* Input Container */}
      <div className="input-container">
        <textarea
          ref={inputRef}
          value={inputValue}
          onChange={(e) => setInputValue(e.target.value)}
          onKeyPress={handleKeyPress}
          placeholder={
            queryMode === 'rag'
              ? "Ask about cybersecurity vulnerabilities, attack patterns, or relationships..."
              : "Ask a question to convert to Cypher query..."
          }
          disabled={isLoading}
          rows={1}
        />
        <button
          onClick={handleSendMessage}
          disabled={isLoading || !inputValue.trim()}
          className="send-button"
        >
          {isLoading ? '...' : 'Send'}
        </button>
      </div>
    </div>
  );
}