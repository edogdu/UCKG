// Helper to generate a random color
function getRandomColor() {
  return `#${Math.floor(Math.random()*16777215).toString(16).padStart(6, '0')}`;
}

// Global label color map to persist colors across queries
const labelColorMap = {};

// Process Neo4j query result
function processQueryResult(query, result) {
  try {
    // Check if this is a graph query by looking for nodes and relationships
    const hasNodes = result.records.some(record => {
      const values = record.toObject();
      return Object.values(values).some(value => 
        value && typeof value === 'object' && 
        (value.labels || value.properties || value.identity !== undefined)
      );
    });

    if (hasNodes) {
      // This is a graph query, process it
      const nodes = [];
      const relationships = [];
      const nodeMap = new Map();
      const relMap = new Map();

      result.records.forEach(record => {
        const values = record.toObject();
        
        // Process each field in the record
        Object.entries(values).forEach(([key, value]) => {
          
          if (value && typeof value === 'object') {
            // Check if it's a node (but not a relationship)
            if ((value.labels || value.properties || value.identity !== undefined) && !value.type) {
              const nodeId = String(value.identity);
              if (!nodeMap.has(nodeId)) {
                const labels = value.labels || [];
                const mainLabel = labels[1] || labels[0];
                
                if (!labelColorMap[mainLabel]) {
                  labelColorMap[mainLabel] = getRandomColor();
                }
                
                const node = {
                  id: nodeId,
                  caption: mainLabel || 'Node',
                  color: labelColorMap[mainLabel],
                  label: mainLabel,
                  properties: value.properties || {}
                };
                
                nodes.push(node);
                nodeMap.set(nodeId, node);
              }
            }
            
            else if (value.type && value.start !== undefined && value.end !== undefined && value.identity !== undefined && !value.labels) {
              const relId = String(value.identity);
              if (!relMap.has(relId)) {
                // Handle both numeric IDs and node objects for start/end
                let fromId, toId;
                
                if (typeof value.start === 'number') {
                  fromId = String(value.start);
                } else if (value.start && value.start.identity !== undefined) {
                  fromId = String(value.start.identity);
                } else if (value.start && value.start.low !== undefined) {
                  fromId = String(value.start.low);
                } else {
                  fromId = String(value.start);
                }
                
                if (typeof value.end === 'number') {
                  toId = String(value.end);
                } else if (value.end && value.end.identity !== undefined) {
                  toId = String(value.end.identity);
                } else if (value.end && value.end.low !== undefined) {
                  toId = String(value.end.low);
                } else {
                  toId = String(value.end);
                }
                
                const relationship = {
                  id: relId,
                  from: fromId,
                  to: toId,
                  caption: value.type,
                  direction: 'forward',
                  arrowColor: 'black',
                  properties: value.properties || {}
                };
                
                relationships.push(relationship);
                relMap.set(relId, relationship);
              }
            }
          } else if (typeof value === 'number') {
            // Handle id() function results - these are just node IDs
            const nodeId = String(value);
            if (!nodeMap.has(nodeId)) {
              const node = {
                id: nodeId,
                caption: 'Node',
                color: getRandomColor(),
                label: 'Node',
                properties: {}
              };
              
              nodes.push(node);
              nodeMap.set(nodeId, node);
            }
          }
        });
      });

      return { 
        type: 'graph', 
        nodes, 
        relationships,
        summary: {
          total_nodes: nodes.length,
          total_relationships: relationships.length
        }
      };
    }
    
    // Reach here means it's not a graph query, process as raw query
    if (result.records && result.records.length > 0) {
      const records = result.records.map(record => {
        const obj = {};
        record.keys.forEach(key => {
          const value = record.get(key);
          // Convert Neo4j integers to regular numbers
          obj[key] = value && value.toNumber ? value.toNumber() : value;
        });
        return obj;
      });
      
      return { 
        type: 'data', 
        records,
        summary: result.summary
      };
    }
    
    return { 
      type: 'data', 
      records: [],
      summary: result.summary
    };
    
  } catch (err) {
    console.log(`Query processing error\n${err}\nCause: ${err.cause}`);
    return { 
      type: 'error', 
      error: err.message,
      nodes: [], 
      relationships: [] 
    };
  }
}

module.exports = {
  processQueryResult
};
