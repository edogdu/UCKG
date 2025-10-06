const express = require('express');
const graphController = require('../controllers/graphController');

const router = express.Router();

// Execute Cypher query
// Comment this route when Q&A Engine is implemented
router.post('/query', graphController.executeQuery);

// Get core labels information
router.get('/labels', graphController.getCoreLabels);

// Get label counts
router.get('/labels/counts', graphController.getLabelCounts);

// Get core label data
router.get('/labels/:labelName', graphController.getCoreLabelData);

// Expand node - get connected nodes and relationships
router.get('/expand/:nodeId', graphController.expandNode);

module.exports = router;

