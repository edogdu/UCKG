const dbConnection = require('../utils/database');
const { processQueryResult } = require('../utils/queryProcessor');

// Core labels configuration
const coreLabels = {
  'UcoCWE': { 
    query: 'MATCH (n:UcoCWE) RETURN n LIMIT 5', 
    countQuery: 'MATCH (n:UcoCWE) RETURN count(n) as count',
    description: 'Common Weakness Enumeration' 
  },
  'UcoCVE': { 
    query: 'MATCH (n:UcoCVE) RETURN n LIMIT 5', 
    countQuery: 'MATCH (n:UcoCVE) RETURN count(n) as count',
    description: 'Common Vulnerabilities and Exposures' 
  },
  'UcoexCPE': { 
    query: 'MATCH (n:UcoexCPE) RETURN n LIMIT 5', 
    countQuery: 'MATCH (n:UcoexCPE) RETURN count(n) as count',
    description: 'Common Platform Enumeration' 
  },
  'UcoexCAPEC': { 
    query: 'MATCH (n:UcoexCAPEC) RETURN n LIMIT 5', 
    countQuery: 'MATCH (n:UcoexCAPEC) RETURN count(n) as count',
    description: 'Common Attack Pattern Enumeration and Classification' 
  },
  'UcoexMITREATTACK': { 
    query: 'MATCH (n:UcoexMITREATTACK) RETURN n LIMIT 5', 
    countQuery: 'MATCH (n:UcoexMITREATTACK) RETURN count(n) as count',
    description: 'MITRE ATT&CK' 
  },
  'UcoexMITRED3FEND': { 
    query: 'MATCH (n:UcoexMITRED3FEND) RETURN n LIMIT 5', 
    countQuery: 'MATCH (n:UcoexMITRED3FEND) RETURN count(n) as count',
    description: 'D3FEND' 
  }
};

// Execute Cypher query
// Comment this function when Q&A Engine is implemented
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
    const result = await dbConnection.executeQuery(query);
    
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

// Get label counts for core labels
exports.getLabelCounts = async (req, res) => {
  try {
    const counts = {};
    
    for (const [labelName, labelConfig] of Object.entries(coreLabels)) {
      try {
        const result = await dbConnection.executeQuery(labelConfig.countQuery);
        if (result.records && result.records.length > 0) {
          const count = result.records[0].get('count');
          counts[labelName] = count.toNumber ? count.toNumber() : count;
        } else {
          counts[labelName] = 0;
        }
      } catch (error) {
        console.error(`Error fetching count for ${labelName}:`, error);
        counts[labelName] = 0;
      }
    }

    res.json({
      success: true,
      data: counts
    });
    
  } catch (error) {
    console.error('Label counts error:', error);
    res.status(500).json({
      success: false,
      message: 'Failed to fetch label counts',
      error: error.message
    });
  }
};

// Get core label data
exports.getCoreLabelData = async (req, res) => {
  try {
    const { labelName } = req.params;
    
    const labelConfig = coreLabels[labelName];
    if (!labelConfig) {
      return res.status(404).json({
        success: false,
        message: 'Label not found'
      });
    }

    const result = await dbConnection.executeQuery(labelConfig.query);
    const processedResult = processQueryResult(labelConfig.query, result);

    res.json({
      success: true,
      data: processedResult,
      labelInfo: {
        name: labelName,
        description: labelConfig.description
      }
    });
    
  } catch (error) {
    console.error('Core label data error:', error);
    res.status(500).json({
      success: false,
      message: 'Failed to fetch core label data',
      error: error.message
    });
  }
};

// Get core labels information
exports.getCoreLabels = async (req, res) => {
  try {
    const labelsInfo = Object.entries(coreLabels).map(([name, config]) => ({
      name,
      description: config.description
    }));

    res.json({
      success: true,
      data: labelsInfo
    });
    
  } catch (error) {
    console.error('Get core labels error:', error);
    res.status(500).json({
      success: false,
      message: 'Failed to fetch core labels',
      error: error.message
    });
  }
};

// Expand node - get connected nodes and relationships
exports.expandNode = async (req, res) => {
  try {
    const { nodeId } = req.params;
    
    if (!nodeId) {
      return res.status(400).json({
        success: false,
        message: 'Node ID is required'
      });
    }

    const query = `MATCH (a)-[r]-(b) WHERE id(a) = ${nodeId} RETURN a, r, b`;
    const result = await dbConnection.executeQuery(query);
    const processedResult = processQueryResult(query, result);

    res.json({
      success: true,
      data: processedResult
    });
    
  } catch (error) {
    console.error('Expand node error:', error);
    res.status(500).json({
      success: false,
      message: 'Failed to expand node',
      error: error.message
    });
  }
};
