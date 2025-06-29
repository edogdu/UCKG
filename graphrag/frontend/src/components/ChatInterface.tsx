import React, { useState, useRef, useEffect } from 'react';
import ReactMarkdown from 'react-markdown';
import { simpleRAGAPI, simpleSampleQuestions, SimpleQueryResponse } from '../services/api';
import './ChatInterface.css';

interface Message {
  id: string;
  content: string;
  role: 'user' | 'assistant';
  timestamp: Date;
  confidence?: number;
  sources?: string[];
  documents?: Array<{
    capec_id: string;
    name: string;
    description: string;
    score: number;
    abstraction?: string;
    severity?: string;
  }>;
  isTyping?: boolean;
}

const ChatInterface: React.FC = () => {
  const [messages, setMessages] = useState<Message[]>([]);
  const [inputValue, setInputValue] = useState('');
  const [isLoading, setIsLoading] = useState(false);
  const [systemStats, setSystemStats] = useState<any>(null);
  const messagesEndRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    scrollToBottom();
  }, [messages]);

  useEffect(() => {
    loadSystemStats();
  }, []);

  const scrollToBottom = () => {
    messagesEndRef.current?.scrollIntoView({ behavior: 'smooth' });
  };

  const loadSystemStats = async () => {
    try {
      const stats = await simpleRAGAPI.getStats();
      setSystemStats(stats.statistics);
    } catch (error) {
      console.error('Failed to load system stats:', error);
    }
  };

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!inputValue.trim() || isLoading) return;

    const userMessage: Message = {
      id: Date.now().toString(),
      content: inputValue,
      role: 'user',
      timestamp: new Date(),
    };

    const typingMessage: Message = {
      id: 'typing',
      content: '',
      role: 'assistant',
      timestamp: new Date(),
      isTyping: true,
    };

    setMessages(prev => [...prev, userMessage, typingMessage]);
    setInputValue('');
    setIsLoading(true);

    try {
      const response: SimpleQueryResponse = await simpleRAGAPI.simpleQuery(inputValue);
      
      // Remove typing indicator
      setMessages(prev => prev.filter(msg => msg.id !== 'typing'));

      const assistantMessage: Message = {
        id: (Date.now() + 1).toString(),
        content: response.answer,
        role: 'assistant',
        timestamp: new Date(),
        confidence: response.confidence,
        sources: response.sources,
        documents: response.documents,
      };

      // Add assistant message with typing effect
      setMessages(prev => [...prev, { ...assistantMessage, content: '' }]);
      
      // Simulate typing effect
      let index = 0;
      const content = response.answer;
      const typingInterval = setInterval(() => {
        if (index < content.length) {
          setMessages(prev => 
            prev.map(msg => 
              msg.id === assistantMessage.id 
                ? { ...msg, content: content.slice(0, index + 1) }
                : msg
            )
          );
          index++;
        } else {
          clearInterval(typingInterval);
          setMessages(prev => 
            prev.map(msg => 
              msg.id === assistantMessage.id 
                ? assistantMessage
                : msg
            )
          );
        }
      }, 5);

    } catch (error) {
      setMessages(prev => prev.filter(msg => msg.id !== 'typing'));
      
      const errorMessage: Message = {
        id: (Date.now() + 1).toString(),
        content: 'I apologize, but I encountered an error processing your request. Please try again.',
        role: 'assistant',
        timestamp: new Date(),
      };
      setMessages(prev => [...prev, errorMessage]);
      console.error('Query failed:', error);
    } finally {
      setIsLoading(false);
    }
  };

  const handleSampleQuestion = (question: string) => {
    setInputValue(question);
  };

  const clearChat = () => {
    setMessages([]);
  };

  const formatConfidence = (confidence?: number) => {
    if (!confidence) return '';
    return `${(confidence * 100).toFixed(0)}%`;
  };

  const TypingIndicator = () => (
    <div className="typing-indicator">
      <div className="typing-dots">
        <div className="typing-dot"></div>
        <div className="typing-dot"></div>
        <div className="typing-dot"></div>
      </div>
    </div>
  );

  return (
    <div className="chat-container">
      {/* Header */}
      <div className="chat-header">
        <div className="header-content">
          <div>
            <h1 className="header-title">UCKG</h1>
            <p className="header-subtitle">Cybersecurity Knowledge Assistant</p>
          </div>
          {systemStats && (
            <div className="header-stats">
              {systemStats.nodes_with_embeddings.toLocaleString()} nodes indexed
            </div>
          )}
        </div>
      </div>

      {/* Messages Area */}
      <div className="messages-area">
        <div className="messages-container">
          {messages.length === 0 ? (
            // Welcome State
            <div className="welcome-state">
              <div>
                <h2 className="welcome-title">
                  How can I help you today?
                </h2>
                <p className="welcome-subtitle">
                  Ask me about cybersecurity attack patterns, vulnerabilities, or defense strategies from our knowledge base.
                </p>
              </div>
              
              {/* Sample Questions */}
              <div className="sample-questions">
                {simpleSampleQuestions.slice(0, 4).map((question, index) => (
                  <button
                    key={index}
                    onClick={() => handleSampleQuestion(question)}
                    className="sample-question"
                    disabled={isLoading}
                  >
                    {question}
                  </button>
                ))}
              </div>
            </div>
          ) : (
            // Chat Messages
            <div className="messages-list">
              {messages.map((message) => (
                <div key={message.id} className="message">
                  <div className="message-header">
                    <div className={`message-avatar ${message.role}`}>
                      {message.role === 'user' ? 'You' : 'AI'}
                    </div>
                    <span className="message-timestamp">
                      {message.timestamp.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })}
                    </span>
                  </div>

                  <div className="message-content">
                    {message.isTyping ? (
                      <TypingIndicator />
                    ) : (
                      <div>
                        <div className="message-text">
                          {message.role === 'assistant' ? (
                            <ReactMarkdown
                              components={{
                                p: ({node, ...props}) => (
                                  <p 
                                    style={{
                                      margin: '0.25rem 0',
                                      lineHeight: '1.5',
                                      display: 'inline-block',
                                      padding: '0',
                                      width: '100%'
                                    }}
                                    {...props}
                                  />
                                ),
                                ul: ({node, ...props}) => (
                                  <ul
                                    style={{
                                      margin: '0.25rem 0',
                                      lineHeight: '1.4',
                                      paddingLeft: '1rem',
                                      paddingRight: '0',
                                      paddingTop: '0',
                                      paddingBottom: '0',
                                      marginLeft: '0',
                                      marginRight: '0',
                                      listStylePosition: 'outside'
                                    }}
                                    {...props}
                                  />
                                ),
                                ol: ({node, ...props}) => (
                                  <ul
                                    style={{
                                      margin: '0.25rem 0',
                                      lineHeight: '1.4',
                                      paddingLeft: '1rem',
                                      paddingRight: '0',
                                      paddingTop: '0',
                                      paddingBottom: '0',
                                      marginLeft: '0',
                                      marginRight: '0',
                                      listStylePosition: 'outside'
                                    }}
                                    {...props}
                                  />
                                ),
                                li: ({node, ...props}) => (
                                  <li
                                    style={{
                                      margin: '0',
                                      lineHeight: '1.4',
                                      paddingLeft: '0',
                                      paddingRight: '0',
                                      paddingTop: '0',
                                      paddingBottom: '0',
                                      display: 'list-item'
                                    }}
                                    {...props}
                                  />
                                ),

                                h1: ({node, ...props}) => <h1 style={{margin: '1rem 0 0.5rem 0', lineHeight: '1.3', padding: '0'}} {...props} />,
                                h2: ({node, ...props}) => <h2 style={{margin: '1rem 0 0.5rem 0', lineHeight: '1.3', padding: '0'}} {...props} />,
                                h3: ({node, ...props}) => <h3 style={{margin: '0.75rem 0 0.5rem 0', lineHeight: '1.3', padding: '0'}} {...props} />,
                                h4: ({node, ...props}) => <h4 style={{margin: '0.75rem 0 0.5rem 0', lineHeight: '1.3', padding: '0'}} {...props} />,
                                h5: ({node, ...props}) => <h5 style={{margin: '0.75rem 0 0.5rem 0', lineHeight: '1.3', padding: '0'}} {...props} />,
                                h6: ({node, ...props}) => <h6 style={{margin: '0.75rem 0 0.5rem 0', lineHeight: '1.3', padding: '0'}} {...props} />,
                              }}
                            >
                              {message.content}
                            </ReactMarkdown>
                          ) : (
                            message.content
                          )}
                        </div>
                        
                        {/* Metadata for assistant messages */}
                        {message.role === 'assistant' && (message.confidence !== undefined || message.sources) && (
                          <div className="message-metadata">
                            <div className="metadata-header">
                              {message.confidence !== undefined && (
                                <span>Confidence: {formatConfidence(message.confidence)}</span>
                              )}
                              {message.sources && message.sources.length > 0 && (
                                <span>{message.sources.length} sources</span>
                              )}
                            </div>
                            
                            {message.sources && message.sources.length > 0 && (
                              <details className="metadata-details">
                                <summary className="metadata-summary">
                                  View sources
                                </summary>
                                <div className="sources-list">
                                  {message.sources.map((source, index) => (
                                    <span
                                      key={index}
                                      className="source-tag"
                                    >
                                      {source}
                                    </span>
                                  ))}
                                </div>
                              </details>
                            )}

                            {message.documents && message.documents.length > 0 && (
                              <details className="metadata-details">
                                <summary className="metadata-summary">
                                  View retrieved documents
                                </summary>
                                <div className="documents-list">
                                  {message.documents.slice(0, 3).map((doc, index) => (
                                    <div key={index} className="document-card">
                                      <div className="document-title">
                                        CAPEC-{doc.capec_id}: {doc.name}
                                      </div>
                                      <div className="document-description">
                                        {doc.description?.substring(0, 150)}...
                                      </div>
                                      <div className="document-footer">
                                        <div className="document-tags">
                                          {doc.severity && (
                                            <span className="tag severity">
                                              {doc.severity}
                                            </span>
                                          )}
                                          {doc.abstraction && (
                                            <span className="tag abstraction">
                                              {doc.abstraction}
                                            </span>
                                          )}
                                        </div>
                                        <span className="document-score">
                                          {(doc.score * 100).toFixed(1)}% match
                                        </span>
                                      </div>
                                    </div>
                                  ))}
                                </div>
                              </details>
                            )}
                          </div>
                        )}
                      </div>
                    )}
                  </div>
                </div>
              ))}
              <div ref={messagesEndRef} />
            </div>
          )}
        </div>
      </div>

      {/* Input Area */}
      <div className="input-area">
        <div className="input-container">
          {messages.length > 0 && (
            <div className="clear-button-container">
              <button
                onClick={clearChat}
                className="clear-button"
              >
                Clear conversation
              </button>
            </div>
          )}
          
          <form onSubmit={handleSubmit} className="input-form">
            <div className="input-wrapper">
              <textarea
                value={inputValue}
                onChange={(e) => setInputValue(e.target.value)}
                onKeyDown={(e) => {
                  if (e.key === 'Enter' && !e.shiftKey) {
                    e.preventDefault();
                    handleSubmit(e);
                  }
                }}
                placeholder="Ask about cybersecurity patterns, vulnerabilities, or defenses..."
                className="message-input"
                disabled={isLoading}
                rows={1}
                onInput={(e) => {
                  const target = e.target as HTMLTextAreaElement;
                  target.style.height = 'auto';
                  target.style.height = Math.min(target.scrollHeight, 128) + 'px';
                }}
              />
              <button
                type="submit"
                disabled={isLoading || !inputValue.trim()}
                className="submit-button"
              >
                <svg
                  width="16"
                  height="16"
                  viewBox="0 0 16 16"
                  fill="none"
                  xmlns="http://www.w3.org/2000/svg"
                >
                  <path
                    d="M.5 1.163A1 1 0 0 1 1.97.28l12.868 6.837a1 1 0 0 1 0 1.766L1.969 15.72A1 1 0 0 1 .5 14.836V10.33a1 1 0 0 1 .816-.983L8.5 8 1.316 6.653A1 1 0 0 1 .5 5.67V1.163Z"
                    fill="currentColor"
                  />
                </svg>
              </button>
            </div>
          </form>
        </div>
      </div>
    </div>
  );
};

export default ChatInterface; 