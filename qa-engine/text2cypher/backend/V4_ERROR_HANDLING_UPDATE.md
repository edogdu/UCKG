# Text2Cypher V4 Error Handling & Fallback Mechanisms

## Overview
This update enhances Text2Cypher V4 with comprehensive error handling, intelligent fallback responses, and user-friendly error messages. Instead of showing empty results or cryptic errors, the system now provides helpful LLM-generated responses and actionable suggestions.

---

## 🚀 Key V4 Error Handling Features

### 1. **Intelligent Empty Results Handling**
**Previous**: Returned empty array with no explanation
**V4**: Provides helpful LLM-generated responses explaining why no results were found

```json
{
  "cypher": "MATCH (cve:UcoCVE) WHERE cve.ucobaseSeverity = 'CRITICAL' RETURN cve",
  "result": [],
  "status": "no_results",
  "message": "No results found for your query. The generated Cypher query was: [query]. Try broadening your search criteria or using different keywords.",
  "count": 0,
  "suggestions": [
    "Try: 'Show CVEs with high severity'",
    "Try: 'Find CVEs affecting Windows platforms'",
    "Try: 'Show recent CVEs'"
  ]
}
```

### 2. **Comprehensive Error Handling**
**Previous**: Threw exceptions and returned HTTP 500 errors
**V4**: Catches all errors and provides structured, helpful responses

```json
{
  "cypher": null,
  "result": [],
  "status": "error",
  "message": "I encountered an error processing your question. Please try rephrasing your question or ask about something else.",
  "count": 0,
  "error": "Validation failed: Nodes should have labels",
  "suggestions": [
    "Try asking about specific node types (CVEs, CWEs, CAPEC patterns, etc.)",
    "Try using broader search terms",
    "Try asking about relationships between different entities"
  ]
}
```

### 3. **LLM-Generated Helpful Responses**
**New Feature**: Uses LLM to generate context-aware, encouraging error messages

**Empty Results Response:**
- Acknowledges that no results were found
- Suggests possible reasons (too specific filters, data might not exist)
- Offers alternative approaches or broader queries
- Maintains encouraging and helpful tone

**Error Response:**
- Acknowledges the error occurred
- Explains what might have gone wrong in simple terms
- Suggests how to rephrase the question
- Offers to help with a different approach

### 4. **Smart Query Suggestions**
**New Feature**: Generates context-aware alternative query suggestions

**CVE-related queries:**
- "Try: 'Show CVEs with high severity'"
- "Try: 'Find CVEs affecting Windows platforms'"
- "Try: 'Show recent CVEs'"

**CWE-related queries:**
- "Try: 'Show CWE weaknesses by status'"
- "Try: 'Find CWE weaknesses related to authentication'"
- "Try: 'Show CWE weaknesses by abstraction level'"

**CAPEC-related queries:**
- "Try: 'Show CAPEC attack patterns by severity'"
- "Try: 'Find CAPEC patterns related to specific weaknesses'"
- "Try: 'Show CAPEC patterns by abstraction level'"

---

## 🔧 Technical Implementation

### New Methods

#### `text_to_cypher_with_fallback(question, schema)`
```python
def text_to_cypher_with_fallback(self, question: str, schema: str = None) -> dict:
    """
    Enhanced text_to_cypher with comprehensive error handling and fallback mechanisms.
    Returns a dictionary with cypher, result, status, and helpful messages.
    """
    try:
        # Generate Cypher query
        cypher = self.text_to_cypher(question, schema)
        
        # Execute query
        result = self.run_cypher(cypher)
        result_list = list(result)
        
        # Check if query returned results
        if not result_list:
            return self._handle_empty_results(question, cypher)
        
        return {
            "cypher": cypher,
            "result": result_list,
            "status": "success",
            "message": f"Query executed successfully. Found {len(result_list)} results.",
            "count": len(result_list)
        }
        
    except Exception as e:
        return self._handle_query_error(question, str(e))
```

#### `_handle_empty_results(question, cypher)`
```python
def _handle_empty_results(self, question: str, cypher: str) -> dict:
    """Handle cases where the query returns no results."""
    try:
        # Generate helpful response using LLM
        fallback_prompt = f"""
You are a cybersecurity knowledge graph assistant. The user asked: "{question}"

The generated Cypher query was: {cypher}

This query returned no results. Provide a helpful response that:
1. Acknowledges that no results were found
2. Suggests possible reasons why (e.g., too specific filters, data might not exist)
3. Offers alternative approaches or broader queries
4. Be encouraging and helpful

Keep the response concise and professional.
"""
        
        helpful_response = self.llm.invoke(fallback_prompt).strip()
        
        return {
            "cypher": cypher,
            "result": [],
            "status": "no_results",
            "message": helpful_response,
            "count": 0,
            "suggestions": self._generate_query_suggestions(question)
        }
```

#### `_handle_query_error(question, error)`
```python
def _handle_query_error(self, question: str, error: str) -> dict:
    """Handle query generation or execution errors."""
    try:
        # Generate helpful error response using LLM
        error_prompt = f"""
You are a cybersecurity knowledge graph assistant. The user asked: "{question}"

An error occurred: {error}

Provide a helpful response that:
1. Acknowledges the error occurred
2. Explains what might have gone wrong in simple terms
3. Suggests how to rephrase the question
4. Offers to help with a different approach

Keep the response encouraging and helpful.
"""
        
        helpful_response = self.llm.invoke(error_prompt).strip()
        
        return {
            "cypher": None,
            "result": [],
            "status": "error",
            "message": helpful_response,
            "count": 0,
            "error": error,
            "suggestions": self._generate_query_suggestions(question)
        }
```

#### `_generate_query_suggestions(question)`
```python
def _generate_query_suggestions(self, question: str) -> list:
    """Generate alternative query suggestions based on the original question."""
    suggestions = []
    
    # Common cybersecurity query patterns
    if any(word in question.lower() for word in ['cve', 'vulnerability', 'vulnerabilities']):
        suggestions.extend([
            "Try: 'Show CVEs with high severity'",
            "Try: 'Find CVEs affecting Windows platforms'",
            "Try: 'Show recent CVEs'"
        ])
    
    if any(word in question.lower() for word in ['cwe', 'weakness', 'weaknesses']):
        suggestions.extend([
            "Try: 'Show CWE weaknesses by status'",
            "Try: 'Find CWE weaknesses related to authentication'",
            "Try: 'Show CWE weaknesses by abstraction level'"
        ])
    
    # ... more patterns for CAPEC, Groups, MITRE, etc.
    
    return suggestions[:5]  # Limit to 5 suggestions
```

### Enhanced API Endpoints

#### `/api/text2cypher` (Enhanced)
```python
@app.post("/api/text2cypher")
def text2cypher_endpoint(req: QueryRequest):
    """Enhanced text2cypher endpoint with comprehensive error handling and fallback responses."""
    try:
        logger.info(f"Processing query: {req.question}")
        schema = t2c.get_schema()
        
        # Use enhanced method with fallback handling
        response = t2c.text_to_cypher_with_fallback(req.question, schema)
        
        logger.info(f"Query status: {response['status']}")
        if response['cypher']:
            logger.info(f"Generated Cypher: {response['cypher']}")
        logger.info(f"Response message: {response['message']}")
        
        return response
        
    except Exception as e:
        logger.error(f"Error processing query: {str(e)}")
        # Return a structured error response instead of raising HTTPException
        return {
            "cypher": None,
            "result": [],
            "status": "error",
            "message": f"I encountered an unexpected error processing your question: '{req.question}'. Please try again or contact support if the issue persists.",
            "count": 0,
            "error": str(e),
            "suggestions": [
                "Try rephrasing your question",
                "Check if the question is about cybersecurity entities (CVEs, CWEs, CAPEC, etc.)",
                "Try asking about specific node types or relationships"
            ]
        }
```

#### `/api/text2cypher/simple` (Backward Compatibility)
```python
@app.post("/api/text2cypher/simple")
def text2cypher_simple_endpoint(req: QueryRequest):
    """Simple text2cypher endpoint for backward compatibility (original behavior)."""
    try:
        logger.info(f"Processing simple query: {req.question}")
        schema = t2c.get_schema()
        cypher = t2c.text_to_cypher(req.question, schema)
        logger.info(f"Generated Cypher: {cypher}")
        result = t2c.run_cypher(cypher)
        result_list = list(result)
        logger.info(f"Query returned {len(result_list)} results")
        return {"cypher": cypher, "result": result_list}
    except Exception as e:
        logger.error(f"Error processing simple query: {str(e)}")
        raise HTTPException(status_code=500, detail=str(e))
```

---

## 📊 Response Format

### Success Response
```json
{
  "cypher": "MATCH (cve:UcoCVE) WHERE cve.ucobaseSeverity = 'HIGH' RETURN cve LIMIT 10",
  "result": [/* query results */],
  "status": "success",
  "message": "Query executed successfully. Found 5 results.",
  "count": 5
}
```

### No Results Response
```json
{
  "cypher": "MATCH (cve:UcoCVE) WHERE cve.ucobaseSeverity = 'CRITICAL' RETURN cve",
  "result": [],
  "status": "no_results",
  "message": "No results found for your query. The generated Cypher query was: [query]. Try broadening your search criteria or using different keywords.",
  "count": 0,
  "suggestions": [
    "Try: 'Show CVEs with high severity'",
    "Try: 'Find CVEs affecting Windows platforms'",
    "Try: 'Show recent CVEs'"
  ]
}
```

### Error Response
```json
{
  "cypher": null,
  "result": [],
  "status": "error",
  "message": "I encountered an error processing your question. Please try rephrasing your question or ask about something else.",
  "count": 0,
  "error": "Validation failed: Nodes should have labels",
  "suggestions": [
    "Try asking about specific node types (CVEs, CWEs, CAPEC patterns, etc.)",
    "Try using broader search terms",
    "Try asking about relationships between different entities"
  ]
}
```

---

## 🎯 Error Handling Scenarios

### 1. **Empty Query Results**
- **Trigger**: Query executes successfully but returns no data
- **Response**: Helpful explanation with suggestions
- **Example**: "Find CVEs with severity CRITICAL" (no CRITICAL CVEs exist)

### 2. **Query Generation Errors**
- **Trigger**: LLM generates invalid Cypher syntax
- **Response**: Error explanation with rephrasing suggestions
- **Example**: "Invalid query with syntax error"

### 3. **Database Connection Errors**
- **Trigger**: Neo4j connection issues
- **Response**: Connection error message with retry suggestions
- **Example**: Database timeout or connection refused

### 4. **Validation Errors**
- **Trigger**: Generated query fails validation checks
- **Response**: Validation error explanation with correction hints
- **Example**: Using wrong node labels or relationship types

### 5. **LLM Service Errors**
- **Trigger**: Ollama/LLM service unavailable
- **Response**: Service error message with fallback suggestions
- **Example**: LLM timeout or service unavailable

---

## 📈 Benefits

### For Users
- ✅ **No More Empty Results**: Always get helpful explanations
- ✅ **Clear Error Messages**: Understand what went wrong
- ✅ **Actionable Suggestions**: Know how to fix the query
- ✅ **Encouraging Tone**: Positive, helpful responses
- ✅ **Context-Aware Help**: Suggestions based on query content

### For Developers
- ✅ **Structured Responses**: Consistent JSON format
- ✅ **Error Classification**: Clear status indicators
- ✅ **Debugging Info**: Error details for troubleshooting
- ✅ **Backward Compatibility**: Original endpoint still available
- ✅ **Comprehensive Logging**: Better monitoring and debugging

### For System Reliability
- ✅ **Graceful Degradation**: Never crashes, always responds
- ✅ **User Experience**: Maintains engagement even with errors
- ✅ **Error Recovery**: Automatic fallback mechanisms
- ✅ **Monitoring**: Better error tracking and analysis

---

## 🔮 Future Enhancements

### Potential V5 Features
1. **Query Learning**: Learn from successful queries to improve suggestions
2. **Error Pattern Recognition**: Identify common error patterns and provide specific fixes
3. **Progressive Query Building**: Guide users through building complex queries step by step
4. **Query History**: Remember previous successful queries for similar requests
5. **Auto-correction**: Automatically fix common query syntax errors

### Advanced Error Handling
1. **Retry Mechanisms**: Automatic retry with different approaches
2. **Query Simplification**: Automatically simplify complex queries that fail
3. **Alternative Query Generation**: Generate multiple query variations
4. **Context-Aware Suggestions**: Use conversation history for better suggestions
5. **Performance Monitoring**: Track query performance and suggest optimizations

---

## 📝 Summary

V4 Error Handling transforms Text2Cypher from a simple query generator into an **intelligent, user-friendly assistant** that:

- **Never leaves users hanging** with empty results or cryptic errors
- **Provides helpful guidance** through LLM-generated responses
- **Offers actionable suggestions** for improving queries
- **Maintains a positive user experience** even when things go wrong
- **Enables graceful error recovery** with comprehensive fallback mechanisms

**Key Achievement**: Text2Cypher now handles all possible error cases gracefully while providing users with helpful, encouraging responses that guide them toward successful queries.

**User Experience**: Instead of "No results found" or "Error 500", users now get intelligent, context-aware responses that help them understand what happened and how to proceed.