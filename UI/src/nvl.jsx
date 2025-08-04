import React, { useEffect, useRef, useState } from 'react';
import { InteractiveNvlWrapper } from '@neo4j-nvl/react';
import { executeQuery, executeCountQuery } from './connection';

// Merges arrays of nodes/relationships by ID, avoiding duplicates.
function mergeElements(oldArr, newArr, key = 'id') {
  const map = new Map(oldArr.map(item => [String(item[key]), item]));
  newArr.forEach(item => {
    const existingItem = map.get(String(item[key]));
    if (existingItem) {
      // Preserve existing properties (including color) and merge new ones
      map.set(String(item[key]), { ...item, ...existingItem });
    } else {
      map.set(String(item[key]), item);
    }
  });
  return Array.from(map.values());
}

// Filters relationships to only those with valid node IDs.
function filterValidRelationships(nodes, relationships) {
  const nodeIds = new Set(nodes.map(n => String(n.id)));
  return relationships.filter(r => nodeIds.has(String(r.from)) && nodeIds.has(String(r.to)));
}

// Core label configurations
const coreLabels = [
  { name: 'UcoCWE', query: 'MATCH (n:UcoCWE) RETURN n LIMIT 5', countQuery: 'MATCH (n:UcoCWE) RETURN count(n) as count', description: 'Common Weakness Enumeration' },
  { name: 'UcoCVE', query: 'MATCH (n:UcoCVE) RETURN n LIMIT 5', countQuery: 'MATCH (n:UcoCVE) RETURN count(n) as count', description: 'Common Vulnerabilities and Exposures' },
  { name: 'UcoexCPE', query: 'MATCH (n:UcoexCPE) RETURN n LIMIT 5', countQuery: 'MATCH (n:UcoexCPE) RETURN count(n) as count', description: 'Common Platform Enumeration' },
  { name: 'UcoexCAPEC', query: 'MATCH (n:UcoexCAPEC) RETURN n LIMIT 5', countQuery: 'MATCH (n:UcoexCAPEC) RETURN count(n) as count', description: 'Common Attack Pattern Enumeration and Classification' },
  { name: 'UcoexMITREATTACK', query: 'MATCH (n:UcoexMITREATTACK) RETURN n LIMIT 5', countQuery: 'MATCH (n:UcoexMITREATTACK) RETURN count(n) as count', description: 'MITRE ATT&CK' },
  { name: 'UcoexMITRED3FEND', query: 'MATCH (n:UcoexMITRED3FEND) RETURN n LIMIT 5', countQuery: 'MATCH (n:UcoexMITRED3FEND) RETURN count(n) as count', description: 'D3FEND' }
];

export default function Nvl() {
  const [cypher, setCypher] = useState('MATCH (n) RETURN n LIMIT 5');
  const [nodes, setNodes] = useState([]);
  const [rels, setRels] = useState([]);
  const [sidePanel, setSidePanel] = useState('');
  const [chatHistory, setChatHistory] = useState([]);
  const [leftPanelOpen, setLeftPanelOpen] = useState(true);
  const [expandedNodes, setExpandedNodes] = useState(new Set()); // Track expanded nodes
  const [previousStates, setPreviousStates] = useState(new Map()); // Store previous states for each node
  const [labelCounts, setLabelCounts] = useState({});
  const chatContainerRef = useRef();
  const wrapperRef = useRef();

  // Fetch initial data and label counts
  useEffect(() => {
    let cancelled = false;
    const fetchData = async () => {
      const { nodes, relationships } = await executeQuery(cypher);
      if (!cancelled) {
        setNodes(nodes);
        setRels(filterValidRelationships(nodes, relationships));
      }
    };
    
    const fetchLabelCounts = async () => {
      const counts = {};
      for (const label of coreLabels) {
        try {
          const count = await executeCountQuery(label.countQuery);
          counts[label.name] = count;
        } catch (error) {
          console.error(`Error fetching count for ${label.name}:`, error);
          counts[label.name] = 0;
        }
      }
      if (!cancelled) {
        setLabelCounts(counts);
      }
    };
    
    fetchData();
    fetchLabelCounts();
    return () => { cancelled = true; };
  }, []); // empty dependency array: only run once on mount

  // Auto-scroll to bottom when chat history changes
  useEffect(() => {
    if (chatContainerRef.current) {
      chatContainerRef.current.scrollTop = chatContainerRef.current.scrollHeight;
    }
  }, [chatHistory]);
  
  // Handle core label button clicks
  const handleLabelClick = async (labelConfig) => {
    const query = labelConfig.query;
    setCypher(query);
    
    // Generate a unique key for this query
    const queryKey = `search_${Date.now()}_${query.trim()}`;
    
    const { nodes, relationships } = await executeQuery(query);
    setNodes(nodes);
    setRels(filterValidRelationships(nodes, relationships));
    
    // Store the result in session storage
    const searchResult = {
      query: query,
      nodes: nodes,
      relationships: relationships,
      timestamp: Date.now()
    };
    sessionStorage.setItem(queryKey, JSON.stringify(searchResult));
    
    setChatHistory(prev => [...prev, { type: 'user', text: query, queryKey }]);
  };

  const mouseEventCallbacks = {
    onHover: (element, hitTargets, evt) => console.log('onHover', element, hitTargets, evt),
    onNodeClick: (node, hitTargets, evt) => {
      console.log('onNodeClick', node, hitTargets, evt);
      if (node?.properties) {
        setSidePanel(
          Object.entries(node.properties)
            .map(([k, v]) => '<b>' + k + '</b>: ' + v)
            .join('<br>')
        );
      } else {
        setSidePanel('');
      }
    },
    onNodeDoubleClick: async (node, hitTargets, evt) => {
      const nodeId = node.id;
      
      // Check if this node is already expanded
      if (expandedNodes.has(nodeId)) {
        // Collapse: restore the previous state
        const previousState = previousStates.get(nodeId);
        if (previousState) {
          setNodes(previousState.nodes);
          setRels(previousState.relationships);
        }
        setExpandedNodes(prev => {
          const newSet = new Set(prev);
          newSet.delete(nodeId);
          return newSet;
        });
        setPreviousStates(prev => {
          const newMap = new Map(prev);
          newMap.delete(nodeId);
          return newMap;
        });
      } else {
        // Store current state before expanding
        setPreviousStates(prev => {
          const newMap = new Map(prev);
          newMap.set(nodeId, { nodes: [...nodes], relationships: [...rels] });
          return newMap;
        });
        
        // Expand: show this node and its relationships
        const query = `MATCH p = (a)-[r]-(b) WHERE id(a) = ${nodeId} RETURN p`;
        const result = await executeQuery(query);
        setNodes(prevNodes => {
          const mergedNodes = mergeElements(prevNodes, result.nodes);
          setRels(prevRels =>
            filterValidRelationships(
              mergedNodes,
              mergeElements(prevRels, result.relationships)
            )
          );
          return mergedNodes;
        });
        setExpandedNodes(prev => new Set([...prev, nodeId]));
      }
    },
    onRelationshipClick: (rel, hitTargets, evt) => {
      console.log('onRelationshipClick', rel, hitTargets, evt);
      if (rel?.properties) {
        setSidePanel(
          Object.entries(rel.properties)
            .map(([k, v]) => '<b>' + k + '</b>: ' + v)
            .join('<br>')
        );
      } else {
        setSidePanel('');
      }
    },
    onCanvasClick: evt => {
      console.log('onCanvasClick', evt);
      setSidePanel('');
    },
    onCanvasDoubleClick: evt => console.log('onCanvasDoubleClick', evt),
    onCanvasRightClick: evt => console.log('onCanvasRightClick', evt),
    onDrag: nodes => console.log('onDrag', nodes),
    onPan: evt => console.log('onPan', evt),
    onZoom: zoomLevel => console.log('onZoom', zoomLevel)
  };

  // Runs the current Cypher query and updates the graph/chat history.
  const handleSearch = async () => {
    if (!cypher.trim()) return;
    
    // Generate a unique key for this query
    const queryKey = `search_${Date.now()}_${cypher.trim()}`;
    
    const { nodes, relationships } = await executeQuery(cypher);
    setNodes(nodes);
    setRels(filterValidRelationships(nodes, relationships));
    
    // Store the result in session storage
    const searchResult = {
      query: cypher,
      nodes: nodes,
      relationships: relationships,
      timestamp: Date.now()
    };
    sessionStorage.setItem(queryKey, JSON.stringify(searchResult));
    
    setChatHistory(prev => [...prev, { type: 'user', text: cypher, queryKey }]);
    setChatHistory(prev => [...prev, { type: 'answer', text: 'answer' }]);
  };

  // Handle clicking on chat history (user message click)
  const handleHistorySearch = async (query, queryKey) => {
    setCypher(query);
    
    // Try to retrieve from session storage first
    if (queryKey && sessionStorage.getItem(queryKey)) {
      try {
        const storedResult = JSON.parse(sessionStorage.getItem(queryKey));
        setNodes(storedResult.nodes);
        setRels(filterValidRelationships(storedResult.nodes, storedResult.relationships));
        console.log('Retrieved result from session storage');
      } catch (error) {
        console.error('Error parsing stored result:', error);
        // Fallback to fresh query if parsing fails
        const { nodes, relationships } = await executeQuery(query);
        setNodes(nodes);
        setRels(filterValidRelationships(nodes, relationships));
      }
    } else {
      // No stored result, fetch fresh data
      const { nodes, relationships } = await executeQuery(query);
      setNodes(nodes);
      setRels(filterValidRelationships(nodes, relationships));
    }
    
    // setChatHistory(prev => [...prev, { type: 'user', text: query, queryKey }]);
    // setChatHistory(prev => [...prev, { type: 'answer', text: 'answer' }]);
  };

  return (
    <div className='Q-n-A'>
      {/* Left Side Panel */}
      <div className={`left-panel ${leftPanelOpen ? 'open' : 'closed'}`}>
        <div className="left-panel-header">
          <h3>Labels</h3>
          <button 
            className="toggle-panel-btn"
            onClick={() => setLeftPanelOpen(!leftPanelOpen)}
          >
            {leftPanelOpen ? '◀' : '▶'}
          </button>
        </div>
        <div className="label-buttons">
          {coreLabels.map((label) => (
            <button
              key={label.name}
              className="label-btn"
              onClick={() => handleLabelClick(label)}
              title={label.description}
            >
              <span className="label-name">{label.name} ({labelCounts[label.name] || 0})</span>
              <span className="label-desc">{label.description}</span>
            </button>
          ))}
        </div>
      </div>

      <div className='graph'>
        <InteractiveNvlWrapper
          ref={wrapperRef}
          nodes={nodes}
          rels={rels}
          mouseEventCallbacks={mouseEventCallbacks}
          nvlOptions={{
            layout: { name: 'forceDirected' },
            relationship: { showArrows: true, arrowColor: 'black', arrowSize: 12 },
            interaction: { dragBackground: true, zoom: true, dragNodes: true },
            node: { 
              preserveColors: true,
              color: 'auto',
              hoverColor: 'auto',
              selectedColor: 'auto',
              expandedColor: 'auto',
              useNodeColors: true,
              maintainOriginalColors: true
            },
            styling: {
              preserveNodeColors: true,
              disableColorChanges: true
            }
          }}
        />
        {/* Overlay for sidePanel in upper right of graph area */}
        {sidePanel && (
          <div className='props' dangerouslySetInnerHTML={{ __html: sidePanel }} />
        )}
      </div>
      <div className='Chat-bot'>
        <div className='Chat-bot-content' ref={chatContainerRef}>
          <ul className='Chat-list'>
            {chatHistory.map((msg, i) => (
              <li
                key={i}
                className={msg.type === 'user' ? 'Chat-list-user' : 'Chat-list-answer'}
                onClick={msg.type === 'user' ? () => handleHistorySearch(msg.text, msg.queryKey) : undefined}
              >
                {msg.text}
              </li>
            ))}
          </ul>
        </div>
        <div className='Input-box'>
          <input
            className='Input-content'
            type='text'
            value={cypher}
            onChange={e => setCypher(e.target.value)}
            onKeyDown={e => e.key === 'Enter' && handleSearch()}
            placeholder='Enter Cypher query'
          />
          <button
            className='Input-button'
            onClick={handleSearch}
          >
            Enter
          </button>
        </div>
      </div>
    </div>
  );
}