# UCKG UI

A React-based web application for visualizing and querying the UCKG (Unified Cybersecurity Knowledge Graph) using Neo4j database.

## Structure

```
UI/
├── frontend/               # Frontend React application
│   ├── App.jsx            # Main application component with routing
│   ├── Home.jsx           # Home page component
│   ├── nvl.jsx            # Graph visualization component
│   ├── connection.js      # API connection utilities
│   ├── index.jsx          # Application entry point
│   └── styles.css         # Application styles
├── backend/               # Backend API server
│   ├── controllers/       # API controllers
│   ├── routers/          # Express routes
│   ├── utils/            # Utility functions
│   └── index.js          # Backend server entry point
├── package.json          # Frontend dependencies
└── webpack.config.js     # Webpack configuration
```

### Prerequisites
- Node.js 
- Neo4j database running
- Docker (for Neo4j)

### 1. Setup Package Files

**IMPORTANT**: Due to .gitignore settings, package.json files are not tracked. You need to rename the provided .txt files:

```bash
# In UI directory
mv package.json.txt package.json

# In UI/backend directory  
cd backend
mv package.json.txt package.json
cd ..
```

### 2. Install Dependencies

**Frontend:**
```bash
npm install
```

**Backend:**
```bash
cd backend
npm install
```

### 3. Configure Environment Variables

Create a `.env` file in the `backend/` directory:
```bash

PORT=3001
NEO4J_URI=bolt://localhost:7687
NEO4J_USER=neo4j
NEO4J_PASSWORD=abcd90909090
FRONTEND_URL=http://localhost:8080
```

### 4. Start Neo4j Database

Run Neo4j using Docker Compose (from project root):
```bash
docker-compose up
```

### 5. Run the Application

**Option 1: Run both frontend and backend together**
```bash
npm run dev
```

**Option 2: Run separately**
```bash
# Terminal 1 - Backend
cd backend
npm start

# Terminal 2 - Frontend(UI folder)
npm start
```

## Available Scripts

### Frontend Scripts
- `npm start` - Start development server (webpack-dev-server)
- `npm run dev` - Run both frontend and backend concurrently

### Backend Scripts
- `npm run backend` - Start backend server
- `npm run backend:dev` - Start backend with nodemon (auto-restart)
