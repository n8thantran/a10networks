# NetSentinel

Real-time network security monitoring and threat detection system powered by AI-driven analysis.

## Overview

NetSentinel is a full-stack cybersecurity demonstration platform that combines real-time packet capture, AI-powered threat analysis, and DDoS attack simulation for educational and defensive security testing purposes.

## Architecture

### Backend (Python/FastAPI)
- **Multi-agent AI workflows** using LangGraph for threat detection
- **Real-time packet capture** with Scapy
- **Natural language network queries** powered by OpenAI GPT-4o-mini
- **WebSocket streaming** for live packet analysis
- **DDoS simulation and protection** with automated detection and mitigation

### Frontend (Next.js/React)
- Real-time security dashboard with live metrics
- Interactive attack simulation panel
- Natural language network query interface
- Attack report visualization with Mermaid diagrams
- Responsive monitoring interface

## Features

### 🛡️ Threat Detection
- XSS (Cross-Site Scripting)
- SQL Injection
- DoS/DDoS attacks
- Port scanning
- Data leakage patterns
- Anomaly detection

### 🔥 Attack Simulation
- Volumetric flood attacks
- Slowloris attacks
- Application layer attacks
- Multi-vector DDoS scenarios
- Configurable intensity and duration

### 📊 Visualization
- Real-time packet stream monitoring
- Threat level heatmaps
- Network topology diagrams
- Attack flow visualizations
- Mitigation strategy diagrams

### 🤖 AI-Powered Analysis
- Natural language query processing
- Automated threat classification
- Attack pattern recognition
- Mitigation recommendations
- Comprehensive attack reports

## Installation

### Prerequisites
- Python 3.8+
- Node.js 16+
- OpenAI API key

### Backend Setup

```bash
cd backend

# Create virtual environment
python3 -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt

# Configure environment
cp .env.example .env
# Edit .env and add your OPENAI_API_KEY

# Run server (requires root for packet capture)
sudo python main_ws.py
```

### Frontend Setup

```bash
cd frontend

# Install dependencies
npm install

# Run development server
npm run dev
```

## Usage

1. **Start Backend**: `sudo python backend/main_ws.py` (runs on port 8000)
2. **Start Frontend**: `npm run dev` in frontend directory (runs on port 3000)
3. **Access Dashboard**: Navigate to `http://localhost:3000`

### Quick Start Guides

**Monitor Network Traffic:**
- Go to Dashboard (`/dashboard`)
- Click "Start Capture" to begin monitoring
- View real-time packets and threat analysis

**Simulate DDoS Attack:**
- Navigate to Attack Panel (`/attack`)
- Configure attack parameters (type, duration, intensity)
- Launch attack and observe AI-driven detection/mitigation

**Query Network Data:**
- Go to Query page (`/query`)
- Ask questions in natural language:
  - "Show recent attack reports"
  - "What protocols are being used?"
  - "Show network topology"

## API Endpoints

### Core Endpoints
- `GET /api/health` - Health check
- `POST /api/query` - Natural language network queries
- `GET /api/network/summary` - Network statistics
- `WS /ws` - WebSocket for real-time packet streaming

### DDoS Simulation
- `POST /api/ddos/start` - Start DDoS simulation
- `POST /api/ddos/stop` - Stop attack
- `GET /api/ddos/status` - Get attack/protection status
- `POST /api/ddos/reset` - Reset protection system

### Reports
- `GET /api/reports` - List all attack reports
- `GET /api/reports/latest` - Get most recent report
- `GET /api/reports/{id}` - Get specific report

## Security Considerations

⚠️ **EDUCATIONAL USE ONLY**

This system is designed for:
- Security research and education
- Defensive security testing
- Network monitoring demonstrations
- Penetration testing training

**DO NOT:**
- Use against systems you don't own
- Deploy without proper authorization
- Use in production environments without security review
- Expose to untrusted networks

## Project Structure

```
├── backend/
│   ├── agents/           # AI agent workflows
│   │   ├── analysis/     # Threat detection agents
│   │   ├── network_query_agent.py
│   │   └── ddos_protection_agent.py
│   ├── storage/          # Data persistence
│   ├── models/           # Data models
│   └── main_ws.py        # Main server
│
└── frontend/
    ├── app/              # Next.js pages
    │   ├── dashboard/    # Main monitoring dashboard
    │   ├── attack/       # Attack simulation panel
    │   └── query/        # Network query interface
    └── components/       # React components
```

## Technologies

**Backend:**
- FastAPI - Web framework
- Scapy - Packet capture
- LangGraph - AI agent orchestration
- OpenAI GPT-4o-mini - Natural language processing
- WebSockets - Real-time communication

**Frontend:**
- Next.js 15 - React framework
- TailwindCSS - Styling
- Mermaid - Diagram rendering
- WebSocket API - Live updates

## Development

### Running Tests
```bash
# Backend tests
cd backend
python test_system.py      # Test network queries
python test_ddos.py        # Test DDoS simulation

# Frontend
cd frontend
npm run lint
```
