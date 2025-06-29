#!/usr/bin/env python3
"""
Setup configuration for the UcoexCAPEC Graph RAG backend package.
"""
from setuptools import setup, find_packages

setup(
    name="ucoex-capec-graphrag",
    version="1.0.0",
    description="Graph RAG system for UcoexCAPEC cybersecurity knowledge",
    packages=find_packages(),
    python_requires=">=3.8",
    install_requires=[
        "fastapi>=0.104.1",
        "uvicorn>=0.24.0",
        "neo4j>=5.17.0",
        "neo4j-graphrag[openai]>=1.6.1",
        "openai>=1.0.0",
        "python-dotenv>=1.0.0",
        "pydantic>=2.5.0",
        "pydantic-settings>=2.1.0",
    ],
    extras_require={
        "dev": [
            "pytest>=7.0.0",
            "pytest-asyncio>=0.21.0",
        ]
    },
    entry_points={
        "console_scripts": [
            "ucoex-check-embeddings=scripts.check_embedding_status:main",
            "ucoex-generate-embeddings=scripts.generate_all_embeddings:main",
            "ucoex-start-api=api.main:app",
        ]
    },
) 