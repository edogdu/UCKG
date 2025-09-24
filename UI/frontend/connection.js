// API base URL for backend
const API_BASE_URL = 'http://localhost:3001/api';

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