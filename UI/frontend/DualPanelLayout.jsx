import React, { useState, useEffect } from 'react';
import ChatInterface from './ChatInterface';
import Nvl from './nvl'; // Your existing graph component

export default function DualPanelLayout() {
  const [activeTab, setActiveTab] = useState('dual');
  const [graphData, setGraphData] = useState({ nodes: [], relationships: [] });
  const [panelSizes, setPanelSizes] = useState({ left: 45, right: 55 });
  const [showGraphNotification, setShowGraphNotification] = useState(false);
  const [queryMode, setQueryMode] = useState('rag');

  // Handle graph updates from chat interface
  const handleGraphUpdate = (newData, sourceMode) => {
    console.log('Updating graph with', newData?.nodes?.length || 0, 'nodes from', sourceMode);

    // Transform the data to match your existing nvl.jsx format
    const transformedData = transformDataForNvl(newData, sourceMode);
    setGraphData(transformedData);

    // Auto-switch to dual panel if not already there
    if (activeTab === 'chat') {
      setActiveTab('dual');
      setShowGraphNotification(true);
      setTimeout(() => setShowGraphNotification(false), 3000);
    }
  };

  // Transform data from RAG/Cypher to NVL format
  const transformDataForNvl = (data, sourceMode) => {
    const nodes = [];
    const relationships = [];

    if (sourceMode === 'rag') {
      // Handle RAG visualization data
      if (data.nodes) {
        data.nodes.forEach(node => {
          nodes.push({
            id: node.id,
            caption: node.label || node.caption || 'Unknown',
            label: node.label || node.caption || 'Unknown',
            properties: {
              ...node.properties,
              isRAGResult: true,
              score: node.score,
              nodeId: node.id, // Add node ID for easy reference
              nodeType: node.type || node.nodeType || 'Unknown',
              mode: 'graphrag',
              // Add content if available
              ...(node.content && { content: node.content })
            },
            // Use Context7 NVL color mapping based on score
            color: node.color || getRAGScoreColor(node.score),
            size: node.size || getRAGScoreSize(node.score)
          });
        });
      }

      if (data.relationships) {
        data.relationships.forEach(rel => {
          relationships.push({
            id: rel.id,
            from: rel.from,
            to: rel.to,
            type: rel.type || rel.label || 'RELATED',
            caption: rel.label || rel.type || 'RELATED',
            properties: {
              ...rel.properties,
              isRAGResult: true
            },
            color: '#00ff00', // Green for RAG relationships
            width: 3
          });
        });
      }
    } else if (sourceMode === 'cypher') {
      // Handle Text2Cypher results
      if (data.nodes) {
        data.nodes.forEach(node => {
          nodes.push({
            id: node.id,
            caption: node.label || node.caption || 'Unknown',
            label: node.label || node.caption || 'Unknown',
            properties: {
              ...node.properties,
              isCypherResult: true
            },
            color: '#4287f5', // Blue for Cypher results
            size: 50
          });
        });
      }

      if (data.relationships) {
        data.relationships.forEach(rel => {
          relationships.push({
            id: rel.id,
            from: rel.from,
            to: rel.to,
            type: rel.type || rel.label || 'RELATED',
            caption: rel.label || rel.type || 'RELATED',
            properties: {
              ...rel.properties,
              isCypherResult: true
            },
            color: '#1a5cd6', // Darker blue for Cypher relationships
            width: 2
          });
        });
      }
    }

    return { nodes, relationships };
  };

  // RAG score-based styling (from Context7 insights)
  const getRAGScoreColor = (score) => {
    if (!score) return '#888888';
    if (score >= 0.9) return '#00ff00'; // High relevance - bright green
    if (score >= 0.8) return '#7fff00'; // Medium-high - chartreuse
    if (score >= 0.7) return '#ffff00'; // Medium - yellow
    if (score >= 0.6) return '#ffa500'; // Medium-low - orange
    return '#ff4500'; // Lower relevance - orange-red
  };

  const getRAGScoreSize = (score) => {
    const baseSize = 20;
    const maxSize = 40;
    return baseSize + ((score || 0) * (maxSize - baseSize));
  };

  const handleTabChange = (tab) => {
    // Only allow 'chat' and 'dual' modes now
    if (tab === 'chat' || tab === 'dual') {
      setActiveTab(tab);
    }
  };

  const handlePanelResize = (direction) => {
    if (direction === 'expand-left') {
      setPanelSizes({ left: 60, right: 40 });
    } else if (direction === 'expand-right') {
      setPanelSizes({ left: 30, right: 70 });
    } else {
      setPanelSizes({ left: 45, right: 55 });
    }
  };

  return (
    <div className="dual-panel-layout">
      {/* Panel Header */}
      <div className="panel-header">
        <div className="tab-controls">
          <button
            className={activeTab === 'chat' ? 'active' : ''}
            onClick={() => handleTabChange('chat')}
            title="Chat only view"
          >
            Q&A Chat
          </button>
          <button
            className={activeTab === 'dual' ? 'active' : ''}
            onClick={() => handleTabChange('dual')}
            title="Interactive chat + graph view"
          >
            Interactive Mode
            {graphData.nodes.length > 0 && (
              <span className="node-count-badge">
                {graphData.nodes.length}
              </span>
            )}
          </button>
        </div>

        {/* Panel sizing controls for dual mode */}
        {activeTab === 'dual' && (
          <div className="panel-controls">
            <button
              onClick={() => handlePanelResize('expand-left')}
              title="Expand graph panel"
              className="panel-resize-btn"
            >
              ← Graph
            </button>
            <button
              onClick={() => handlePanelResize('reset')}
              title="Reset panel sizes"
              className="panel-resize-btn"
            >
              Reset
            </button>
            <button
              onClick={() => handlePanelResize('expand-right')}
              title="Expand chat panel"
              className="panel-resize-btn"
            >
              Chat →
            </button>
          </div>
        )}

        {/* Current mode indicator */}
        <div className="mode-indicator">
          Mode: <span className="current-mode">{queryMode.toUpperCase()}</span>
        </div>
      </div>

      {/* Graph notification overlay */}
      {showGraphNotification && (
        <div className="graph-notification">
          <div className="notification-content">
            Graph automatically updated with query results!
            <button onClick={() => setShowGraphNotification(false)}>✕</button>
          </div>
        </div>
      )}

      {/* Panel Content */}
      <div className="panel-content">
        {activeTab === 'dual' ? (
          <div className="dual-panels">
            {/* Left Panel - Graph Visualization */}
            <div
              className="left-panel graph-panel"
              style={{ width: `${panelSizes.left}%` }}
            >
              {graphData.nodes.length === 0 ? (
                <div className="graph-empty-state">
                  <div className="empty-state-content">
                    <div className="empty-state-icon">
                      <svg width="80" height="80" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5">
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
                    </div>
                    <h3>No Visualization Yet</h3>
                    <p>Ask a question to see the knowledge graph visualization with related nodes and relationships.</p>

                    <div className="empty-state-suggestions">
                      <div className="suggestion-title">TRY ASKING:</div>
                      <div className="suggestion-buttons">
                        <button className="suggestion-btn">What is CWE-89?</button>
                        <button className="suggestion-btn">SQL injection relationships</button>
                        <button className="suggestion-btn">High severity CVEs</button>
                      </div>
                    </div>
                  </div>
                </div>
              ) : (
                <Nvl
                  key={`graph-${graphData.nodes.length}-${Date.now()}`}
                  initialNodes={graphData.nodes}
                  initialRels={graphData.relationships}
                  minimal={true}
                />
              )}
            </div>

            {/* Panel Divider */}
            <div className="panel-divider" />

            {/* Right Panel - Chat Interface */}
            <div
              className="right-panel chat-panel"
              style={{ width: `${panelSizes.right}%` }}
            >
              <ChatInterface
                onGraphUpdate={handleGraphUpdate}
                onModeChange={setQueryMode}
              />
            </div>
          </div>
        ) : (
          <div className="single-panel">
            <ChatInterface
              onGraphUpdate={handleGraphUpdate}
              onModeChange={setQueryMode}
            />

            {/* Floating mini graph indicator */}
            {graphData.nodes.length > 0 && (
              <div className="mini-graph-indicator" onClick={() => handleTabChange('dual')}>
                <div className="indicator-text">
                  {graphData.nodes.length} nodes available - Click to view graph
                </div>
              </div>
            )}
          </div>
        )}
      </div>
    </div>
  );
}