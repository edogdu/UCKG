import { nvlResultTransformer } from '@neo4j-nvl/base';
import neo4j from 'neo4j-driver';

// Add the username and password
const URI = 'bolt://localhost:7687';
const USER = '';
const PASSWORD = '';

// Helper to generate a random color
function getRandomColor() {
   return `#${Math.floor(Math.random()*16777215).toString(16).padStart(6, '0')}`;
}

export const executeQuery = async (query) => {
   let driver;
   try {
      // Connect to neo4j database
      driver = neo4j.driver(URI, neo4j.auth.basic(USER, PASSWORD));
      const data = await driver.executeQuery(query, {}, { resultTransformer: nvlResultTransformer });

      // Map to store label => color
      const labelColorMap = {};

      // Map to get the nodes from the query
      const nodes = data.nodes.map((n) => {
         const { properties, labels } = data.recordObjectMap.get(n.id ?? n.identity);
         // Use the second label as the main label
         const mainLabel = labels?.[1];
         const firstLabel = labels?.[0];
         // Assign a color if this label hasn't been seen yet
         if (!labelColorMap[mainLabel]) {
            labelColorMap[mainLabel] = getRandomColor();
         }
         return {
            ...n,
            id: String(n.id ?? n.identity),
            // caption: properties.label ?? properties.ucocweID ?? mainLabel ?? firstLabel,
            caption: mainLabel ?? firstLabel,
            color: labelColorMap[mainLabel],
            label: mainLabel,
            uri: properties.uri,
            properties
         };
      });

      // Map to get the rels from the query
      const relationships = data.relationships.map(r => {
         const or = data.recordObjectMap.get(r.id);
         return {
            ...r,
            id: String(r.id),
            from: String(r.from),
            to: String(r.to),
            caption: or?.type ?? r.type,
            direction: 'forward',
            arrowColor: 'black'
         };
      });

      // Check if the nodes and rels are defined
      console.log("RAW nodes:", nodes);
      console.log("RAW relationships:", relationships);

      // Return them
      return { nodes, relationships };
   } catch (err) {
      // If the connection is error, the arrays of nodes and rels will be empty
      console.log(`Connection error\n${err}\nCause: ${err.cause}`);
      return { nodes: [], relationships: [] };
   } finally {
      // End the connection
      if (driver) await driver.close();
   }
};

// New function specifically for count queries
export const executeCountQuery = async (query) => {
   let driver;
   try {
      // Connect to neo4j database
      driver = neo4j.driver(URI, neo4j.auth.basic(USER, PASSWORD));
      const result = await driver.executeQuery(query);
      
      // Extract the count value from the result
      if (result.records && result.records.length > 0) {
         const record = result.records[0];
         const count = record.get('count');
         return count.toNumber ? count.toNumber() : count;
      }
      
      return 0;
   } catch (err) {
      console.log(`Count query error\n${err}\nCause: ${err.cause}`);
      return 0;
   } finally {
      // End the connection
      if (driver) await driver.close();
   }
};