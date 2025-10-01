#!/usr/bin/env node

/**
 * UCKG UI Health Check Script
 * Diagnoses connection issues between UI components and backend services
 */

const fetch = require('node-fetch');
const { exec } = require('child_process');
const util = require('util');

const execAsync = util.promisify(exec);

// Color codes for output
const colors = {
    red: '\x1b[31m',
    green: '\x1b[32m',
    yellow: '\x1b[33m',
    blue: '\x1b[34m',
    magenta: '\x1b[35m',
    cyan: '\x1b[36m',
    reset: '\x1b[0m'
};

function log(color, message) {
    console.log(`${colors[color]}${message}${colors.reset}`);
}

function logStatus(status, message) {
    const icon = status ? '[OK]' : '[FAIL]';
    const color = status ? 'green' : 'red';
    log(color, `${icon} ${message}`);
}

async function checkPort(port, serviceName) {
    try {
        const { stdout } = await execAsync(`lsof -Pi :${port} -sTCP:LISTEN -t`);
        const pid = stdout.trim();
        if (pid) {
            logStatus(true, `${serviceName} (port ${port}) is running (PID: ${pid})`);
            return true;
        }
    } catch (error) {
        logStatus(false, `${serviceName} (port ${port}) is not running`);
        return false;
    }
}

async function checkHTTPEndpoint(url, serviceName, expectedContent = null) {
    try {
        const response = await fetch(url, { timeout: 5000 });
        
        if (response.ok) {
            const text = await response.text();
            
            if (expectedContent && !text.includes(expectedContent)) {
                logStatus(false, `${serviceName} responded but content unexpected`);
                log('yellow', `  Expected: ${expectedContent}`);
                log('yellow', `  Got: ${text.substring(0, 100)}...`);
                return false;
            }
            
            logStatus(true, `${serviceName} HTTP endpoint is healthy`);
            return true;
        } else {
            logStatus(false, `${serviceName} returned status ${response.status}`);
            return false;
        }
    } catch (error) {
        logStatus(false, `${serviceName} HTTP endpoint failed: ${error.message}`);
        return false;
    }
}

async function checkNeo4jConnection() {
    try {
        const neo4j = require('neo4j-driver');
        const driver = neo4j.driver(
            'bolt://localhost:7687',
            neo4j.auth.basic('neo4j', 'abcd90909090')
        );
        
        await driver.verifyConnectivity();
        await driver.close();
        
        logStatus(true, 'Neo4j database connection successful');
        return true;
    } catch (error) {
        logStatus(false, `Neo4j database connection failed: ${error.message}`);
        return false;
    }
}

async function checkPythonEnvironment() {
    try {
        const { stdout } = await execAsync('python3 --version');
        log('green', `Python version: ${stdout.trim()}`);
        
        // Check if MultiRAG wrapper exists
        const fs = require('fs');
        const wrapperPath = '../qa-engine/multirag_wrapper.py';
        
        if (fs.existsSync(wrapperPath)) {
            logStatus(true, 'MultiRAG wrapper script found');
            
            // Try to run a simple test
            try {
                const { stdout, stderr } = await execAsync(`cd ../qa-engine && python3 multirag_wrapper.py --help`, { timeout: 10000 });
                if (stdout.includes('usage') || stdout.includes('MultiRAG')) {
                    logStatus(true, 'MultiRAG wrapper is executable');
                    return true;
                } else {
                    logStatus(false, 'MultiRAG wrapper help command failed');
                    if (stderr) log('yellow', `  Error: ${stderr}`);
                    return false;
                }
            } catch (error) {
                logStatus(false, `MultiRAG wrapper test failed: ${error.message}`);
                return false;
            }
        } else {
            logStatus(false, 'MultiRAG wrapper script not found at ../qa-engine/multirag_wrapper.py');
            return false;
        }
    } catch (error) {
        logStatus(false, `Python environment check failed: ${error.message}`);
        return false;
    }
}

async function testAPIEndpoints() {
    log('blue', '\nTesting API Endpoints...');
    
    const endpoints = [
        {
            url: 'http://localhost:3001/api/graph/labels',
            name: 'Graph Labels Endpoint',
            expectedContent: null
        },
        {
            url: 'http://localhost:8000',
            name: 'Text2Cypher Health Check',
            expectedContent: 'healthy'
        },
        {
            url: 'http://localhost:8000/api/schema',
            name: 'Text2Cypher Schema Endpoint',
            expectedContent: null
        }
    ];
    
    let allPassed = true;
    
    for (const endpoint of endpoints) {
        const result = await checkHTTPEndpoint(endpoint.url, endpoint.name, endpoint.expectedContent);
        if (!result) allPassed = false;
    }
    
    return allPassed;
}

async function testRAGQuery() {
    log('blue', '\n🤖 Testing RAG Query...');
    
    try {
        const response = await fetch('http://localhost:3001/api/qna/rag', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
                query: 'What is CWE-89?',
                mode: 'auto',
                top_k: 3
            }),
            timeout: 30000
        });
        
        if (response.ok) {
            const result = await response.json();
            if (result.success && result.data && result.data.answer) {
                logStatus(true, 'RAG query test successful');
                log('cyan', `  Answer preview: ${result.data.answer.substring(0, 100)}...`);
                return true;
            } else {
                logStatus(false, 'RAG query returned unexpected format');
                log('yellow', `  Response: ${JSON.stringify(result, null, 2)}`);
                return false;
            }
        } else {
            const errorText = await response.text();
            logStatus(false, `RAG query failed with status ${response.status}`);
            log('yellow', `  Error: ${errorText}`);
            return false;
        }
    } catch (error) {
        logStatus(false, `RAG query test failed: ${error.message}`);
        return false;
    }
}

async function main() {
    log('cyan', '🏥 UCKG UI Health Check\n');
    
    let allHealthy = true;
    
    // Check basic services
    log('blue', 'Checking Service Ports...');
    const portChecks = await Promise.all([
        checkPort(3000, 'React Frontend'),
        checkPort(3001, 'Express Backend'),
        checkPort(8000, 'Text2Cypher FastAPI'),
        checkPort(7687, 'Neo4j Database'),
        checkPort(7474, 'Neo4j Browser')
    ]);
    
    if (!portChecks.every(Boolean)) allHealthy = false;
    
    // Check database connection
    log('blue', '\nChecking Database Connection...');
    const dbHealthy = await checkNeo4jConnection();
    if (!dbHealthy) allHealthy = false;
    
    // Check Python environment
    log('blue', '\n🐍 Checking Python Environment...');
    const pythonHealthy = await checkPythonEnvironment();
    if (!pythonHealthy) allHealthy = false;
    
    // Check API endpoints
    const apiHealthy = await testAPIEndpoints();
    if (!apiHealthy) allHealthy = false;
    
    // Test RAG functionality
    if (portChecks[1] && portChecks[2]) { // Backend and Text2Cypher running
        const ragHealthy = await testRAGQuery();
        if (!ragHealthy) allHealthy = false;
    } else {
        log('yellow', '\nSkipping RAG test - required services not running');
    }
    
    // Final status
    log('blue', '\nHealth Check Summary');
    if (allHealthy) {
        log('green', 'All systems are healthy! Your UI should be working correctly.');
    } else {
        log('red', 'Some issues detected. Please fix the failing checks above.');
        
        log('yellow', '\nQuick fixes:');
        log('yellow', '   • Start Neo4j: neo4j start');
        log('yellow', '   • Install Python deps: cd ../qa-engine && pip install -r requirements.txt');
        log('yellow', '   • Start all services: ./start-services.sh');
    }
    
    process.exit(allHealthy ? 0 : 1);
}

if (require.main === module) {
    main().catch(console.error);
}

module.exports = { checkPort, checkHTTPEndpoint, checkNeo4jConnection };
