const express = require('express');
const qnaController = require('../controllers/Q&AController');

const router = express.Router();

// Q&A Engine endpoints - unified FastAPI service
router.post('/rag', qnaController.ragQuery);
router.post('/text2cypher', qnaController.text2cypherQuery);

module.exports = router;