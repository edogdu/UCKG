// API base URL for backend
const API_BASE_URL = 'http://localhost:3001/api';

// ========== NEW Q&A INTEGRATION FUNCTIONS ==========

// Execute RAG query - implements your plan's chat interface
export const executeRAGQuery = async (query, mode = 'auto') => {
  try {
    const response = await fetch(`${API_BASE_URL}/qna/rag`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({
        query,
        mode,
        top_k: 5,
        include_visualization: true
      })
    });

    if (!response.ok) {
      throw new Error(`HTTP error! status: ${response.status}`);
    }

    const result = await response.json();

    if (result.success) {
      return result.data;
    } else {
      throw new Error(result.message || 'RAG query failed');
    }
  } catch (err) {
    console.error(`RAG query error: ${err}`);
    throw err;
  }
};

// Execute Text2Cypher query - converts natural language to Cypher
export const executeText2Cypher = async (query) => {
  try {
    const response = await fetch(`${API_BASE_URL}/qna/text2cypher`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({
        query: query,
        execute: true,
        explain: true
      })
    });

    if (!response.ok) {
      throw new Error(`HTTP error! status: ${response.status}`);
    }

    const result = await response.json();

    if (result.success) {
      return result.data;
    } else {
      throw new Error(result.message || 'Text2Cypher query failed');
    }
  } catch (err) {
    console.error(`Text2Cypher query error: ${err}`);
    throw err;
  }
};

// Combined intelligent query executor - auto-detects query type
export const executeIntelligentQuery = async (query) => {
  try {
    // Detect if it's likely a raw Cypher query
    const cypherKeywords = ['MATCH', 'RETURN', 'WITH', 'CREATE', 'MERGE', 'DELETE', 'SET'];
    const isLikelyCypher = cypherKeywords.some(keyword =>
      query.toUpperCase().includes(keyword)
    );

    if (isLikelyCypher) {
      // Execute as traditional Cypher query
      return executeQuery(query);
    } else {
      // Execute as RAG query for natural language
      return executeRAGQuery(query);
    }
  } catch (err) {
    console.error(`Intelligent query error: ${err}`);
    throw err;
  }
};

// ========== EXISTING GRAPH FUNCTIONS ==========

// Execute query via backend API
// change this to Q&A Engine query
export const executeQuery = async (query) => {
   try {
      const response = await fetch(`${API_BASE_URL}/graph/query`, { // change this to Q&A Engine query /qna/query
         method: 'POST',
         headers: {
            'Content-Type': 'application/json',
         },
         body: JSON.stringify({ query })
      });

      if (!response.ok) {
         throw new Error(`HTTP error! status: ${response.status}`);
      }

      const result = await response.json();
      
      if (result.success) {
         return result.data;
      } else {
         return {
            type: 'error',
            error: result.message,
            nodes: [],
            relationships: []
         };
      }
   } catch (err) {
      console.log(`API query error: ${err}`);
      return {
         type: 'error',
         error: err.message,
         nodes: [],
         relationships: []
      };
   }
};

// Get core labels information via backend API
export const getCoreLabels = async () => {
   try {
      const response = await fetch(`${API_BASE_URL}/graph/labels`);
      
      if (!response.ok) {
         throw new Error(`HTTP error! status: ${response.status}`);
      }

      const result = await response.json();
      
      if (result.success) {
         return result.data;
      } else {
         console.error('Failed to fetch core labels:', result.message);
         return [];
      }
   } catch (err) {
      console.error('Core labels API error:', err);
      return [];
   }
};

// Get label counts via backend API
export const getLabelCounts = async () => {
   try {
      const response = await fetch(`${API_BASE_URL}/graph/labels/counts`);
      
      if (!response.ok) {
         throw new Error(`HTTP error! status: ${response.status}`);
      }

      const result = await response.json();
      
      if (result.success) {
         return result.data;
      } else {
         console.error('Failed to fetch label counts:', result.message);
         return {};
      }
   } catch (err) {
      console.error('Label counts API error:', err);
      return {};
   }
};

// Get core label data via backend API
export const getCoreLabelData = async (labelName) => {
   try {
      const response = await fetch(`${API_BASE_URL}/graph/labels/${labelName}`);
      
      if (!response.ok) {
         throw new Error(`HTTP error! status: ${response.status}`);
      }

      const result = await response.json();
      
      if (result.success) {
         return result.data;
      } else {
         return {
            type: 'error',
            error: result.message,
            nodes: [],
            relationships: []
         };
      }
   } catch (err) {
      console.log(`Core label data API error: ${err}`);
      return {
         type: 'error',
         error: err.message,
         nodes: [],
         relationships: []
      };
   }
};

// Expand node - get connected nodes and relationships via backend API
export const expandNode = async (nodeId) => {
   try {
      const response = await fetch(`${API_BASE_URL}/graph/expand/${nodeId}`);
      
      if (!response.ok) {
         throw new Error(`HTTP error! status: ${response.status}`);
      }

      const result = await response.json();
      
      if (result.success) {
         return result.data;
      } else {
         return {
            type: 'error',
            error: result.message,
            nodes: [],
            relationships: []
         };
      }
   } catch (err) {
      console.log(`Expand node API error: ${err}`);
      return {
         type: 'error',
         error: err.message,
         nodes: [],
         relationships: []
      };
   }
};