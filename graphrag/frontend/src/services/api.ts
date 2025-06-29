import axios from 'axios';

// Create axios instance with base configuration
const api = axios.create({
  baseURL: process.env.REACT_APP_API_URL || 'http://localhost:8000',
  timeout: 30000,
  headers: {
    'Content-Type': 'application/json',
  },
});

// Add request interceptor for debugging
api.interceptors.request.use(
  (config) => {
    console.log('API Request:', config.method?.toUpperCase(), config.url);
    return config;
  },
  (error) => {
    return Promise.reject(error);
  }
);

// Add response interceptor for error handling
api.interceptors.response.use(
  (response) => {
    return response;
  },
  (error) => {
    console.error('API Error:', error.response?.data || error.message);
    return Promise.reject(error);
  }
);

// Types for the simplified API
export interface SimpleQueryRequest {
  question: string;
  top_k?: number;
  include_sources?: boolean;
}

export interface SimpleQueryResponse {
  answer: string;
  confidence: number;
  query: string;
  sources?: string[];
  documents?: Array<{
    capec_id: string;
    name: string;
    description: string;
    score: number;
    abstraction?: string;
    severity?: string;
    likelihood?: string;
    mitigations?: string | string[];
    skills_required?: string | string[];
    prerequisites?: string | string[];
    content?: string;
  }>;
}

export interface SimpleHealthResponse {
  status: string;
  version: string;
  statistics?: {
    total_capec_nodes: number;
    nodes_with_embeddings: number;
    embedding_coverage: number;
    embedding_dimension: number;
    vector_index_name: string;
  };
}

export interface SimpleSampleQuestionsResponse {
  questions: string[];
}

export interface SimpleStatsResponse {
  status: string;
  statistics: {
    total_capec_nodes: number;
    nodes_with_embeddings: number;
    embedding_coverage: number;
    embedding_dimension: number;
    vector_index_name: string;
  };
}

// Simple Vector RAG API Service
class SimpleVectorRAGAPIService {
  
  // Health check endpoint
  async checkHealth(): Promise<SimpleHealthResponse> {
    const response = await api.get<SimpleHealthResponse>('/health');
    return response.data;
  }

  // Main Vector RAG query endpoint
  async queryRAG(request: SimpleQueryRequest): Promise<SimpleQueryResponse> {
    const response = await api.post<SimpleQueryResponse>('/api/rag/query', request);
    return response.data;
  }

  // Get sample questions
  async getSampleQuestions(): Promise<SimpleSampleQuestionsResponse> {
    const response = await api.get<SimpleSampleQuestionsResponse>('/api/rag/sample-questions');
    return response.data;
  }

  // Get system statistics
  async getStats(): Promise<SimpleStatsResponse> {
    const response = await api.get<SimpleStatsResponse>('/api/rag/statistics');
    return response.data;
  }

  // Regenerate embeddings (admin operation)
  async regenerateEmbeddings(): Promise<{ status: string; message: string }> {
    const response = await api.post('/api/rag/regenerate-embeddings');
    return response.data;
  }

  // Debug vector search
  async vectorSearchDebug(query: string, top_k = 5): Promise<{
    query: string;
    documents: any[];
    count: number;
  }> {
    const response = await api.post('/api/rag/vector-search', null, {
      params: { query, top_k }
    });
    return response.data;
  }

  // Convenience method for simple queries
  async simpleQuery(question: string, includeSources = true): Promise<SimpleQueryResponse> {
    return this.queryRAG({
      question,
      top_k: 5,
      include_sources: includeSources
    });
  }

  // Convenience method for CAPEC-specific queries
  async queryCAPEC(capecId: string): Promise<SimpleQueryResponse> {
    return this.queryRAG({
      question: `Tell me about CAPEC-${capecId}`,
      top_k: 3,
      include_sources: true
    });
  }
}

// Export singleton instance
export const simpleRAGAPI = new SimpleVectorRAGAPIService();

// Export for testing or custom usage
export { SimpleVectorRAGAPIService };

// Sample questions optimized for vector search
export const simpleSampleQuestions = [
  "What is SQL injection and how can it be prevented?",
  "What are common privilege escalation techniques?",
  "How do cross-site scripting attacks work?",
  "What mitigations exist for buffer overflow attacks?",
  "What are the most critical web application vulnerabilities?",
  "How can man-in-the-middle attacks be detected?",
  "What techniques are used for credential stuffing?",
  "How do denial of service attacks work?",
  "What are common social engineering techniques?",
  "How can organizations protect against insider threats?"
];

export default simpleRAGAPI; 