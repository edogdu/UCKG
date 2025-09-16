# Cybersecurity Text2Cypher Frontend

A React-based frontend for the Cybersecurity Text2Cypher Assistant, designed specifically for cybersecurity knowledge graphs built with unified cybersecurity ontologies (UCO).

## Features

### 🛡️ Cybersecurity-Focused Interface
- **Specialized UI**: Designed specifically for cybersecurity queries
- **Category Organization**: Sample queries organized by cybersecurity domains
- **Visual Indicators**: Color-coded categories for different security entities

### 📊 Query Categories
- **🔴 CVE Vulnerabilities**: Common Vulnerabilities and Exposures
- **🟡 CWE Weaknesses**: Common Weakness Enumeration
- **🟢 CAPEC Attack Patterns**: Common Attack Pattern Enumeration
- **🔵 Threat Intelligence**: Threat groups, software, campaigns
- **🟣 Advanced Queries**: Complex property-based queries

### 💡 Sample Queries
Based on actual cybersecurity knowledge graph properties:

#### CVE Queries
- "Show all CVEs with HIGH severity"
- "Find CVEs with exploitability score greater than 8"
- "Show CVEs that require user interaction"

#### CWE Queries
- "Find CWE weakness with ID CWE-13"
- "Show CWE weaknesses with Draft status"

#### CAPEC Queries
- "Find CAPEC pattern with ID 16"
- "Show CAPEC patterns with High severity"

#### Threat Intelligence
- "Find threat group named Gallmaker"
- "Find software named Socksbot"
- "Show threat groups in enterprise-attack domain"

## Getting Started

### Prerequisites
- Node.js (v14 or higher)
- npm or yarn
- Backend service running on `http://localhost:8001`

### Installation

1. **Install dependencies**:
   ```bash
   npm install
   ```

2. **Start the development server**:
   ```bash
   npm start
   ```

3. **Open your browser**:
   Navigate to `http://localhost:3000`

### Environment Variables

Create a `.env` file in the frontend directory:

```env
REACT_APP_API_URL=http://localhost:8001
```

## Usage

### Basic Query
1. Enter your cybersecurity question in the input field
2. Click "Generate Cypher" or press Enter
3. View the generated Cypher query and results
4. Copy the query or results using the copy buttons

### Sample Queries
- Click on any sample query button to populate the input field
- Queries are organized by cybersecurity categories
- Each category has specific property-based examples

### Query History
- View recent queries in the history section
- Reuse previous queries by clicking "Reuse"
- Clear history when needed

## UI Features

### 🎨 Cybersecurity Theme
- Dark cybersecurity-themed color scheme
- Gradient backgrounds with security-focused colors
- Glassmorphism design elements

### 📱 Responsive Design
- Mobile-friendly interface
- Adaptive layout for different screen sizes
- Touch-friendly buttons and controls

### 🔍 Visual Feedback
- Loading states during query generation
- Error handling with user-friendly messages
- Success indicators for copied content

## API Integration

The frontend communicates with the backend via:

- **POST** `/api/text2cypher` - Generate Cypher queries
- **GET** `/api/schema` - Get cybersecurity schema information
- **GET** `/docs` - Health check endpoint

## Query Types Supported

### Property-Based Queries
- Finding nodes by specific properties (severity, status, ID)
- Filtering by exact property matches (domain, abstraction)
- Searching for specific text in properties (names, descriptions)

### Relationship Queries
- Following cybersecurity relationships between entities
- Finding related vulnerabilities, weaknesses, and attack patterns
- Identifying threat actor connections and software usage

### Complex Queries
- Multi-property filters
- Relationship + property combinations
- Statistical queries and counting

## Development

### Project Structure
```
src/
├── App.js              # Main application component
├── App.css             # Cybersecurity-themed styles
├── api.js              # API service for backend communication
├── index.js            # Application entry point
└── index.css           # Global styles
```

### Key Components

#### App.js
- Main application logic
- Query handling and state management
- Sample query organization by categories
- History management

#### api.js
- Backend communication service
- Error handling and validation
- Health check functionality

#### App.css
- Cybersecurity-themed styling
- Category-specific color coding
- Responsive design rules
- Glassmorphism effects

## Customization

### Adding New Sample Queries
Edit the `sampleQueries` array in `App.js`:

```javascript
const sampleQueries = [
  "Your new cybersecurity query here",
  // ... existing queries
];
```

### Modifying Categories
Update the category sections in `App.js`:

```javascript
<div className="category">
  <h4>🆕 New Category</h4>
  <div className="sample-grid">
    {/* Your new queries */}
  </div>
</div>
```

### Styling Changes
Modify `App.css` to adjust:
- Color schemes
- Layout spacing
- Button styles
- Category-specific colors

## Troubleshooting

### Common Issues

1. **Backend Connection Error**
   - Ensure the backend is running on the correct port
   - Check the `REACT_APP_API_URL` environment variable
   - Verify network connectivity

2. **Query Generation Fails**
   - Check the browser console for error details
   - Ensure the query uses cybersecurity-specific terms
   - Verify the backend is properly configured

3. **Styling Issues**
   - Clear browser cache
   - Restart the development server
   - Check for CSS conflicts

## Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Test thoroughly
5. Submit a pull request

## License

This project is part of the UCKG (Unified Cybersecurity Knowledge Graph) project.
