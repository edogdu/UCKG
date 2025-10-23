const fetch = require('node-fetch');
const { processQueryResult } = require('../utils/queryProcessor');
const dbConnection = require('../utils/database');
const graphController = require('./graphController');

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
    const qaEngineUrl = process.env.QA_ENGINE_URL || 'http://localhost:8001';
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

// Text2Cypher Query Handler - Generate Cypher and use graphController for visualization
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

    // Call Q&A Engine FastAPI service to generate Cypher and explanation
    const qaEngineUrl = process.env.QA_ENGINE_URL || 'http://localhost:8001';
    const response = await fetch(`${qaEngineUrl}/api/text2cypher`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        question: query,
        execute: execute,  // Execute in Python to get LLM explanation
        explain: explain
      })
    });

    if (!response.ok) {
      throw new Error(`Q&A Engine service error: ${response.status}`);
    }

    const result = await response.json();
    const cypherQuery = result.cypher_query;

    console.log(`Generated Cypher: ${cypherQuery}`);

    // Execute the Cypher query using graphController's method (gets proper graph_data for visualization)
    let graph_data = null;
    if (execute && cypherQuery) {
      try {
        const graphResult = await dbConnection.executeQuery(cypherQuery);
        graph_data = processQueryResult(cypherQuery, graphResult);
        console.log(`Graph data processed: ${graph_data.nodes?.length || 0} nodes, ${graph_data.relationships?.length || 0} relationships`);
      } catch (error) {
        console.error('Error executing Cypher query:', error);
        graph_data = { type: 'error', nodes: [], relationships: [], error: error.message };
      }
    }

    // Return combined result with graph data from Node.js backend
    res.json({
      success: true,
      data: {
        answer: result.answer,
        chat_data: result.chat_data,
        cypher_query: cypherQuery,
        explanation: result.explanation,
        confidence: result.confidence,
        query_validated: result.query_validated,
        graph_data: graph_data  // Use graph_data from Node.js processQueryResult (for proper visualization)
      }
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