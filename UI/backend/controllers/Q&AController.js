// const dbConnection = require('../utils/database');
const qnaEngine = require('../../qnaEngine'); //Fix this path with Q&A Engine entry file
const { processQueryResult } = require('../utils/queryProcessor');

  
  // Execute Cypher query
  exports.executeQuery = async (req, res) => {
    try {
      const { query } = req.body;
      
      if (!query) {
        return res.status(400).json({
          success: false,
          message: 'Query is required'
        });
      }
  
      // Execute the query
      // const result = await dbConnection.executeQuery(query);
      const result = await qnaEngine.executeQuery(query);
      
      // Process the result
      const processedResult = processQueryResult(query, result);
      
      res.json({
        success: true,
        data: processedResult
      });
      
    } catch (error) {
      console.error('Query execution error:', error);
      res.status(500).json({
        success: false,
        message: 'Query execution failed',
        error: error.message
      });
    }
  };