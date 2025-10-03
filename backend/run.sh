#!/bin/bash

echo "Starting Gloq Network Security Monitor Backend..."

# Check if running as root (recommended for packet capture)
if [ "$EUID" -ne 0 ]; then 
    echo "Warning: Not running as root. Packet capture may require sudo privileges."
    echo "Consider running: sudo ./run.sh"
fi

# Check for Python
if ! command -v python3 &> /dev/null; then
    echo "Python 3 is not installed. Please install Python 3.8 or higher."
    exit 1
fi

# Create virtual environment if it doesn't exist
if [ ! -d "venv" ]; then
    echo "Creating virtual environment..."
    python3 -m venv venv
fi

# Activate virtual environment
source venv/bin/activate

# Install requirements
echo "Installing requirements..."
pip install -q -r requirements.txt

# Check for .env file
if [ ! -f ".env" ]; then
    echo "No .env file found. Creating from example..."
    cp .env.example .env
    echo "Please edit .env file with your API keys before running."
    exit 1
fi

# Load environment variables
export $(cat .env | xargs)

# Start the FastAPI server
echo "Starting FastAPI server on http://localhost:8000"
echo "API documentation available at http://localhost:8000/docs"
python main.py