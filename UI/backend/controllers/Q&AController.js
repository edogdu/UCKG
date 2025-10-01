const fetch = require('node-fetch');

// RAG Query Handler - Calls unified FastAPI service
exports.ragQuery = async (req, res) => {
  try {
    const { query, mode = 'auto', top_k = 5, include_visualization = true } = req.body;

    if (!query) {
      return res.status(400).json({
        success: false,
        message: 'Query is required'
      });
    }

    console.log(`Processing RAG query: ${query} (mode: ${mode})`);

    // Call unified Q&A Engine FastAPI service
    const qaEngineUrl = process.env.QA_ENGINE_URL || 'http://localhost:8000';
    const response = await fetch(`${qaEngineUrl}/api/rag`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ 
        query, 
        mode, 
        top_k, 
        include_visualization 
      })
    });

    if (!response.ok) {
      throw new Error(`Q&A Engine service error: ${response.status}`);
    }

    const ragResult = await response.json();

    res.json({
      success: true,
      data: ragResult
    });

  } catch (error) {
    console.error('RAG query error:', error);
    res.status(500).json({
      success: false,
      message: 'RAG query failed',
      error: error.message
    });
  }
};

// Text2Cypher Query Handler - Calls unified FastAPI service
exports.text2cypherQuery = async (req, res) => {
  try {
    const { query, execute = true, explain = true } = req.body;

    if (!query) {
      return res.status(400).json({
        success: false,
        message: 'Query is required'
      });
    }

    console.log(`Processing Text2Cypher query: ${query}`);

    // Call unified Q&A Engine FastAPI service
    const qaEngineUrl = process.env.QA_ENGINE_URL || 'http://localhost:8000';
    const response = await fetch(`${qaEngineUrl}/api/text2cypher`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ 
        question: query, 
        execute, 
        explain 
      })
    });

    if (!response.ok) {
      throw new Error(`Q&A Engine service error: ${response.status}`);
    }

    const result = await response.json();

    res.json({
      success: true,
      data: result
    });

  } catch (error) {
    console.error('Text2Cypher error:', error);
    res.status(500).json({
      success: false,
      message: 'Text2Cypher query failed',
      error: error.message
    });
  }
};

// The Express.js controller now simply forwards requests to the unified FastAPI service