"""
Simplified FastAPI server for testing without packet capture
"""
import asyncio
import json
import logging
from typing import Dict, Any, List
from fastapi import FastAPI, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse, JSONResponse
from pydantic import BaseModel
import uvicorn
from datetime import datetime, timezone
import os
from dotenv import load_dotenv

load_dotenv()

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

app = FastAPI(title="NetSentinel Security Testing")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Simple threat detection without agents for testing
class ThreatDetector:
    def __init__(self):
        self.xss_patterns = [
            "<script", "javascript:", "onerror=", "onclick=", 
            "alert(", "document.cookie", "<iframe"
        ]
        self.sql_patterns = [
            "' or '", "1=1", "union select", "drop table",
            "; delete", "exec(", "xp_cmdshell"
        ]
    
    def detect_threats(self, text: str) -> Dict[str, Any]:
        threats = []
        text_lower = text.lower()
        
        # Check XSS
        for pattern in self.xss_patterns:
            if pattern.lower() in text_lower:
                threats.append({
                    "type": "XSS",
                    "pattern": pattern,
                    "severity": "high"
                })
        
        # Check SQL Injection
        for pattern in self.sql_patterns:
            if pattern.lower() in text_lower:
                threats.append({
                    "type": "SQL Injection",
                    "pattern": pattern,
                    "severity": "critical"
                })
        
        threat_level = "safe"
        if threats:
            if any(t["severity"] == "critical" for t in threats):
                threat_level = "critical"
            elif any(t["severity"] == "high" for t in threats):
                threat_level = "high"
            else:
                threat_level = "medium"
        
        return {
            "threats": threats,
            "threat_level": threat_level,
            "timestamp": datetime.now(timezone.utc).isoformat()
        }

detector = ThreatDetector()

# Test data storage
test_submissions = []

class TestSubmission(BaseModel):
    username: str = ""
    password: str = ""
    email: str = ""
    comment: str = ""
    search: str = ""

@app.get("/")
async def root():
    return {"message": "NetSentinel Security Testing API", "docs": "/docs", "test": "/test"}

@app.get("/test", response_class=HTMLResponse)
async def test_page():
    """Vulnerable test page for security testing"""
    return """
    <!DOCTYPE html>
    <html>
    <head>
        <title>NetSentinel Security Test Site</title>
        <style>
            body { 
                font-family: Arial, sans-serif; 
                max-width: 800px; 
                margin: 50px auto; 
                padding: 20px;
                background: #f0f0f0;
            }
            .container {
                background: white;
                padding: 30px;
                border-radius: 10px;
                box-shadow: 0 2px 10px rgba(0,0,0,0.1);
            }
            h1 { color: #333; }
            .form-section {
                margin: 30px 0;
                padding: 20px;
                border: 1px solid #ddd;
                border-radius: 5px;
            }
            input, textarea {
                width: 100%;
                padding: 10px;
                margin: 10px 0;
                border: 1px solid #ddd;
                border-radius: 4px;
                box-sizing: border-box;
            }
            button {
                background: #007bff;
                color: white;
                padding: 10px 20px;
                border: none;
                border-radius: 4px;
                cursor: pointer;
            }
            button:hover { background: #0056b3; }
            .results {
                margin-top: 20px;
                padding: 15px;
                background: #f8f9fa;
                border-radius: 5px;
                display: none;
            }
            .threat-critical { color: #dc3545; font-weight: bold; }
            .threat-high { color: #fd7e14; font-weight: bold; }
            .threat-medium { color: #ffc107; }
            .threat-safe { color: #28a745; }
            .vulnerable-display {
                margin: 10px 0;
                padding: 10px;
                background: #fff3cd;
                border: 1px solid #ffc107;
                border-radius: 4px;
            }
        </style>
    </head>
    <body>
        <div class="container">
            <h1>🔒 NetSentinel Security Test Environment</h1>
            <p>This is an intentionally vulnerable page for testing security detection. Try various injection attacks!</p>
            
            <!-- Login Form (SQL Injection Test) -->
            <div class="form-section">
                <h2>Login Form (SQL Injection Test)</h2>
                <form id="loginForm">
                    <input type="text" id="username" placeholder="Username (try: admin' OR '1'='1)" />
                    <input type="password" id="password" placeholder="Password" />
                    <button type="submit">Login</button>
                </form>
                <div class="vulnerable-display" id="loginQuery"></div>
            </div>
            
            <!-- Search Box (XSS Test) -->
            <div class="form-section">
                <h2>Search (XSS Test)</h2>
                <form id="searchForm">
                    <input type="text" id="search" placeholder="Search (try: <script>alert('XSS')</script>)" />
                    <button type="submit">Search</button>
                </form>
                <div class="vulnerable-display" id="searchDisplay"></div>
            </div>
            
            <!-- Comment Form (Mixed Injection Test) -->
            <div class="form-section">
                <h2>Comment Form (Mixed Injection Test)</h2>
                <form id="commentForm">
                    <input type="email" id="email" placeholder="Email" />
                    <textarea id="comment" rows="4" placeholder="Comment (try various payloads)"></textarea>
                    <button type="submit">Submit Comment</button>
                </form>
                <div class="vulnerable-display" id="commentDisplay"></div>
            </div>
            
            <!-- Results Display -->
            <div id="results" class="results">
                <h3>🛡️ Threat Analysis Results:</h3>
                <div id="threatInfo"></div>
            </div>
        </div>
        
        <script>
            async function analyzeInput(data) {
                const response = await fetch('/api/test/analyze', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify(data)
                });
                return response.json();
            }
            
            function displayResults(analysis) {
                const results = document.getElementById('results');
                const threatInfo = document.getElementById('threatInfo');
                
                results.style.display = 'block';
                
                let threatClass = 'threat-' + analysis.threat_level;
                let html = `<p class="${threatClass}">Threat Level: ${analysis.threat_level.toUpperCase()}</p>`;
                
                if (analysis.threats && analysis.threats.length > 0) {
                    html += '<h4>Detected Threats:</h4><ul>';
                    analysis.threats.forEach(threat => {
                        html += `<li><strong>${threat.type}</strong>: Pattern "${threat.pattern}" (Severity: ${threat.severity})</li>`;
                    });
                    html += '</ul>';
                } else {
                    html += '<p>No threats detected in this input.</p>';
                }
                
                threatInfo.innerHTML = html;
            }
            
            // Login Form Handler
            document.getElementById('loginForm').addEventListener('submit', async (e) => {
                e.preventDefault();
                const username = document.getElementById('username').value;
                const password = document.getElementById('password').value;
                
                // Show "vulnerable" SQL query
                document.getElementById('loginQuery').innerHTML = 
                    `<strong>Simulated SQL:</strong> SELECT * FROM users WHERE username='${username}' AND password='${password}'`;
                
                const analysis = await analyzeInput({ username, password });
                displayResults(analysis);
            });
            
            // Search Form Handler
            document.getElementById('searchForm').addEventListener('submit', async (e) => {
                e.preventDefault();
                const search = document.getElementById('search').value;
                
                // Show "vulnerable" display (safely escaped for demo)
                document.getElementById('searchDisplay').innerHTML = 
                    `<strong>Search results for:</strong> ${search.replace(/</g, '&lt;').replace(/>/g, '&gt;')}`;
                
                const analysis = await analyzeInput({ search });
                displayResults(analysis);
            });
            
            // Comment Form Handler
            document.getElementById('commentForm').addEventListener('submit', async (e) => {
                e.preventDefault();
                const email = document.getElementById('email').value;
                const comment = document.getElementById('comment').value;
                
                // Show "vulnerable" display
                document.getElementById('commentDisplay').innerHTML = 
                    `<strong>Comment from ${email}:</strong><br>${comment.replace(/</g, '&lt;').replace(/>/g, '&gt;')}`;
                
                const analysis = await analyzeInput({ email, comment });
                displayResults(analysis);
            });
        </script>
    </body>
    </html>
    """

@app.post("/api/test/analyze")
async def analyze_test_input(submission: TestSubmission):
    """Analyze test input for security threats"""
    # Combine all fields for analysis
    full_text = f"{submission.username} {submission.password} {submission.email} {submission.comment} {submission.search}"
    
    # Detect threats
    analysis = detector.detect_threats(full_text)
    
    # Store submission for review
    test_submissions.append({
        "data": submission.model_dump(),
        "analysis": analysis,
        "timestamp": datetime.now(timezone.utc).isoformat()
    })
    
    return analysis

@app.get("/api/test/submissions")
async def get_submissions():
    """Get all test submissions for review"""
    return {"submissions": test_submissions[-50:]}  # Last 50 submissions

@app.get("/api/health")
async def health():
    return {"status": "healthy", "test_endpoint": "/test"}

if __name__ == "__main__":
    print("🚀 Starting NetSentinel Test Server")
    print("🧪 Test page: http://localhost:8000/test")
    print("📚 API docs: http://localhost:8000/docs")
    uvicorn.run(app, host="0.0.0.0", port=8000)