const neo4j = require('neo4j-driver');

class DatabaseConnection {
  constructor() {
    this.driver = null;
  }

  async connect() {
    try {
      this.driver = neo4j.driver(
        process.env.NEO4J_URI,
        neo4j.auth.basic(
          process.env.NEO4J_USER,
          process.env.NEO4J_PASSWORD
        )
      );
      
      // Test the connection
      await this.driver.verifyConnectivity();
      console.log('Connected to Neo4j database');
      return true;
    } catch (error) {
      console.error('Failed to connect to Neo4j:', error);
      return false;
    }
  }

  async executeQuery(query) {
    if (!this.driver) {
      throw new Error('Database not connected');
    }

    try {
      const result = await this.driver.executeQuery(query);
      return result;
    } catch (error) {
      console.error('Query execution error:', error);
      throw error;
    }
  }

  async close() {
    if (this.driver) {
      await this.driver.close();
      this.driver = null;
      console.log('Database connection closed');
    }
  }
}

// Singleton instance
const dbConnection = new DatabaseConnection();

module.exports = dbConnection;
