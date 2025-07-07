import React, { useEffect, useRef, useState } from "react";
import { InteractiveNvlWrapper } from "@neo4j-nvl/react";
import { executeQuery } from "./connection";

// Merges two arrays of nodes or rels to add new elements to the graph without duplicates
function mergeElements(oldArr, newArr, key = "id") {
  const map = new Map(oldArr.map(item => [String(item[key]), item]));
  newArr.forEach(item => map.set(String(item[key]), item));
  return Array.from(map.values());
}

// Ensures only rels have endpoints in nodes are kept
// Prevent errors in the visualization
function filterValidRelationships(nodes, relationships) {
  const nodeIds = new Set(nodes.map(n => String(n.id)));
  return relationships.filter(
    r => nodeIds.has(String(r.from)) && nodeIds.has(String(r.to))
  );
}

export default function Nvl() {
  // cypher: current Cypher query
  // nodes: array of graph nodes
  // sidePanel: node properties
  // wrapperRef: ref for nvl wrapper
  const [cypher, setCypher] = useState("MATCH (n) RETURN n LIMIT 5");
  const [nodes, setNodes] = useState([]);
  const [rels, setRels] = useState([]);
  const [sidePanel, setSidePanel] = useState("");
  const wrapperRef = useRef();

  // Initial load and cypher search
  useEffect(() => {
    let cancelled = false;
    // execute the new query and update nodes and rels
    const fetchData = async () => {
      const { nodes, relationships } = await executeQuery(cypher);
      if (!cancelled) {
        setNodes(nodes);
        // Make sure only valid rels shown
        setRels(filterValidRelationships(nodes, relationships));
      }
    };
    fetchData();
    return () => { cancelled = true; };
  }, [cypher]);

  // Mouse event callbacks
  // Note: after double-click on the node, to move (hover) nodes, click on the canvas before click back and move the node.
  const mouseEventCallbacks = {
    onHover: (element, hitTargets, evt) =>
      console.log('onHover', element, hitTargets, evt),
    onNodeClick: (node, hitTargets, evt) => {
      console.log('onNodeClick', node, hitTargets, evt);
      if (node?.properties) {
        setSidePanel(
          Object.entries(node.properties)
            .map(([k, v]) => `<b>${k}</b>: ${v}`)
            .join("<br>")
        );
      } else {
        setSidePanel("");
      }
    },
    onNodeDoubleClick: async (node, hitTargets, evt) => {
      console.log('onNodeDoubleClick', node, hitTargets, evt);
      const query = `MATCH p = (a)-[r]-(b) WHERE id(a) = ${node.id} RETURN p;`;
      const result = await executeQuery(query);
      setNodes(prevNodes => {
        const mergedNodes = mergeElements(prevNodes, result.nodes);
        setRels(prevRels =>
          filterValidRelationships(
            mergedNodes,
            mergeElements(prevRels, result.relationships)
          )
        );
        return mergedNodes;
      });
    },
    onRelationshipClick: (rel, hitTargets, evt) => {
      console.log('onRelationshipClick', rel, hitTargets, evt);
      if (rel?.properties) {
        setSidePanel(
          Object.entries(rel.properties)
            .map(([k, v]) => `<b>${k}</b>: ${v}`)
            .join("<br>")
        );
      } else {
        setSidePanel("");
      }
    },
    onCanvasClick: (evt) => console.log('onCanvasClick', evt),
    onCanvasDoubleClick: (evt) => console.log('onCanvasDoubleClick', evt),
    onCanvasRightClick: (evt) => console.log('onCanvasRightClick', evt),
    onDrag: (nodes) => console.log('onDrag', nodes),
    onPan: (evt) => console.log('onPan', evt),
    onZoom: (zoomLevel) => console.log('onZoom', zoomLevel)
  };

  // Cypher search input
  const handleSearch = async () => {
    if (!cypher.trim()) return;
    const { nodes, relationships } = await executeQuery(cypher);
    setNodes(nodes);
    setRels(filterValidRelationships(nodes, relationships));
  };

  return (
    <div style={{ display: "flex", height: "100vh" }}>
      <div style={{ flex: 1, position: "relative", padding: "1px" }}>
        <div>
          <input
            type="text"
            value={cypher}
            onChange={e => setCypher(e.target.value)}
            onKeyDown={e => e.key === "Enter" && handleSearch()}
            style={{ width: "70%" }}
            placeholder="Enter Cypher query"
          />
          <button onClick={handleSearch}>Search</button>
        </div>
        <InteractiveNvlWrapper
          ref={wrapperRef}
          nodes={nodes}
          rels={rels}
          mouseEventCallbacks={mouseEventCallbacks}
          nvlOptions={{
            layout: { name: "forceDirected" },
            relationship: { showArrows: true, arrowColor: "black", arrowSize: 12 },
            interaction: {
              dragBackground: true,
              zoom: true,
              dragNodes: true
            }
          }}
          style={{
            width: "100%",
            height: "90%",
            border: "1px solid #ccc",
            background: "#fff"
          }}
        />
      </div>
      <div
        id="side-panel"
        style={{
          width: 250,
          borderLeft: "1px solid #ccc",
          padding: 12,
          background: "#f8f8f8",
          overflowY: "auto"
        }}
        dangerouslySetInnerHTML={{ __html: sidePanel }}
      />
    </div>
  );
}