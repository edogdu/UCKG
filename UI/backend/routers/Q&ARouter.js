const express = require('express');
const qnaController = require('../controllers/Q&AController');

const router = express.Router();

// Execute Cypher query
router.post('/query', qnaController.executeQuery);

module.exports = router;