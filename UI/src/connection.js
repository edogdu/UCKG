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


// Universal query execution function that handles both graph and non-graph results
export const executeQuery = async (query) => {
   let driver;
   try {
      // Connect to neo4j database
      driver = neo4j.driver(URI, neo4j.auth.basic(USER, PASSWORD));
      
      // First try with nvlResultTransformer to see if it's a graph query
      try {
         const graphData = await driver.executeQuery(query, {}, { resultTransformer: nvlResultTransformer });
         
         // Check if we got meaningful graph data
         if (graphData.nodes && graphData.nodes.length > 0) {
            // This is a graph query, process it like before
            const labelColorMap = {};
            
            const nodes = graphData.nodes.map((n) => {
               const { properties, labels } = graphData.recordObjectMap.get(n.id ?? n.identity);
               const mainLabel = labels?.[1];
               const firstLabel = labels?.[0];
               
               if (!labelColorMap[mainLabel]) {
                  labelColorMap[mainLabel] = getRandomColor();
               }
               
               return {
                  ...n,
                  id: String(n.id ?? n.identity),
                  caption: mainLabel ?? firstLabel,
                  color: labelColorMap[mainLabel],
                  label: mainLabel,
                  uri: properties.uri,
                  properties
               };
            });
            
            const relationships = graphData.relationships.map(r => {
               const or = graphData.recordObjectMap.get(r.id);
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
            
            return { 
               type: 'graph', 
               nodes, 
               relationships 
            };
         }
      } catch (graphError) {
         // If nvlResultTransformer fails, it's likely not a graph query
         console.log('Not a graph query, trying raw execution');
      }
      
      // If we reach here, it's not a graph query, execute as raw query
      const result = await driver.executeQuery(query);
      
      if (result.records && result.records.length > 0) {
         const records = result.records.map(record => {
            const obj = {};
            record.keys.forEach(key => {
               const value = record.get(key);
               // Convert Neo4j integers to regular numbers
               obj[key] = value && value.toNumber ? value.toNumber() : value;
            });
            return obj;
         });
         
         return { 
            type: 'data', 
            records,
            summary: result.summary
         };
      }
      
      return { 
         type: 'data', 
         records: [],
         summary: result.summary
      };
      
   } catch (err) {
      console.log(`Universal query error\n${err}\nCause: ${err.cause}`);
      return { 
         type: 'error', 
         error: err.message,
         nodes: [], 
         relationships: [] 
      };
   } finally {
      if (driver) await driver.close();
   }
};