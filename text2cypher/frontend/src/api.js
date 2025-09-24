// API service for Cybersecurity Text2Cypher frontend
const API_BASE_URL = process.env.REACT_APP_API_URL || 'http://localhost:8001';

class Text2CypherAPI {
  async query(question) {
    try {
      const response = await fetch(`${API_BASE_URL}/api/text2cypher`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({ question }),
      });

      if (!response.ok) {
        const errorData = await response.json().catch(() => ({}));
        throw new Error(errorData.detail || `HTTP error! status: ${response.status}`);
      }

      const data = await response.json();
      
      // Ensure we have the expected structure
      if (!data.cypher) {
        throw new Error('Invalid response format: missing Cypher query');
      }

      return data;
    } catch (error) {
      console.error('API Error:', error);
      
      // Provide user-friendly error messages
      if (error.message.includes('Failed to fetch')) {
        throw new Error('Unable to connect to the Text2Cypher service. Please check if the backend is running.');
      }
      
      throw error;
    }
  }

  async healthCheck() {
    try {
      const response = await fetch(`${API_BASE_URL}/docs`);
      return response.ok;
    } catch (error) {
      console.error('Health check failed:', error);
      return false;
    }
  }

  async getSchema() {
    try {
      const response = await fetch(`${API_BASE_URL}/api/schema`);
      
      if (!response.ok) {
        throw new Error(`HTTP error! status: ${response.status}`);
      }

      return await response.json();
    } catch (error) {
      console.error('Schema fetch error:', error);
      throw error;
    }
  }

  async chatHistory(sessionId, question) {
    try {
      const response = await fetch(`${API_BASE_URL}/api/chat_history`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ session_id: sessionId, question })
      });
      if (!response.ok) {
        const errorData = await response.json().catch(() => ({}));
        throw new Error(errorData.detail || `HTTP error! status: ${response.status}`);
      }
      return await response.json();
    } catch (error) {
      console.error('Chat history API error:', error);
      throw error;
    }
  }
}

export const text2CypherAPI = new Text2CypherAPI();
export default text2CypherAPI; 