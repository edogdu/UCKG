require('dotenv').config();
const express = require('express');
const cors = require('cors');
const dbConnection = require('./utils/database');

// Import routers
const graphRouter = require('./routers/graphRouter');
// const Q&ARouter = require('./routers/Q&ARouter');

const app = express();

// Middleware
app.use(cors({
  origin: process.env.FRONTEND_URL,
  credentials: true
}));
app.use(express.json());

// Routes
app.use('/api/graph', graphRouter);
// app.use('/api/qna', Q&ARouter);


// Initialize database connection and start server
async function startServer() {
  try {
    // Connect to database
    const connected = await dbConnection.connect();
    if (!connected) {
      console.error('Failed to connect to database. Server will not start.');
      process.exit(1);
    }

    // Start server
    const PORT = process.env.PORT;
    app.listen(PORT, () => {
      console.log(`UCKG Backend API server is running on port ${PORT}`);
    });
  } catch (error) {
    console.error('Failed to start server:', error);
    process.exit(1);
  }
}

// Handle graceful shutdown
process.on('SIGINT', async () => {
  console.log('Shutting down server...');
  await dbConnection.close();
  process.exit(0);
});

process.on('SIGTERM', async () => {
  console.log('Shutting down server...');
  await dbConnection.close();
  process.exit(0);
});

startServer();
