"""
Configuration module for UcoexCAPEC Graph RAG system.
Based on Neo4j GraphRAG Python package documentation.
"""
import os
from typing import Optional
from pydantic_settings import BaseSettings
from pydantic import Field
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

class Settings(BaseSettings):
    """Application settings based on Neo4j GraphRAG best practices."""
    
    # Neo4j Configuration
    neo4j_uri: str = Field(default="bolt://localhost:7687", env="NEO4J_URI")
    neo4j_user: str = Field(default="neo4j", env="NEO4J_USER") 
    neo4j_password: str = Field(env="NEO4J_PASSWORD")  # Required - no default for security
    
    # OpenAI Configuration
    openai_api_key: Optional[str] = Field(default=None, env="OPENAI_API_KEY")
    
    # Vector Index Configuration
    ucoex_capec_index_name: str = Field(default="ucoex_capec_embeddings", env="UCOEX_CAPEC_INDEX_NAME")
    vector_dimension: int = Field(default=1536, env="VECTOR_DIMENSION")
    top_k_results: int = Field(default=5, env="TOP_K_RESULTS")
    
    # Application Configuration
    app_host: str = Field(default="0.0.0.0", env="APP_HOST")
    app_port: int = Field(default=8000, env="APP_PORT")
    debug: bool = Field(default=True, env="DEBUG")
    
    # Model Configuration
    embedding_model: str = Field(default="text-embedding-3-large", env="EMBEDDING_MODEL")
    llm_model: str = Field(default="gpt-4o", env="LLM_MODEL")
    llm_temperature: float = Field(default=0.0, env="LLM_TEMPERATURE")
    
    # CORS Configuration
    cors_origins: list = ["http://localhost:3000", "http://localhost:3001"]
    
    class Config:
        env_file = ".env"
        case_sensitive = False

# Global settings instance
settings = Settings()

def get_neo4j_config() -> dict:
    """Get Neo4j connection configuration."""
    return {
        "uri": settings.neo4j_uri,
        "auth": (settings.neo4j_user, settings.neo4j_password)
    }

def get_openai_config() -> dict:
    """Get OpenAI configuration for GraphRAG."""
    return {
        "api_key": settings.openai_api_key,
        "embedding_model": settings.embedding_model,
        "llm_model": settings.llm_model,
        "temperature": settings.llm_temperature
    }

def get_vector_config() -> dict:
    """Get vector index configuration."""
    return {
        "index_name": settings.ucoex_capec_index_name,
        "dimensions": settings.vector_dimension,
        "top_k": settings.top_k_results
    } 