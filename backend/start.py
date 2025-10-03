#!/usr/bin/env python3
"""
Simple startup script - no sudo needed
"""
import os
import sys

print("=" * 50)
print("🚀 NetSentinel Security Testing Server")
print("=" * 50)

# Check which mode to run
if len(sys.argv) > 1 and sys.argv[1] == "--full":
    print("Running FULL mode with AI agents...")
    
    # Check for .env file
    if not os.path.exists(".env"):
        print("\nCreating .env from template...")
        if os.path.exists(".env.example"):
            with open(".env.example", "r") as src, open(".env", "w") as dst:
                dst.write(src.read())
            print("✅ Created .env - please add your OPENAI_API_KEY")
            sys.exit(1)
    
    # Load environment variables
    from dotenv import load_dotenv
    load_dotenv()
    
    if not os.getenv("OPENAI_API_KEY"):
        print("\n❌ OPENAI_API_KEY not set in .env file")
        print("   Get your key from: https://platform.openai.com/api-keys")
        sys.exit(1)
    
    print("\n📚 API Docs: http://localhost:8000/docs")
    print("🧪 Test Site: http://localhost:8000/test")
    print("\nPress Ctrl+C to stop\n")
    os.system("python main.py")
else:
    print("Running SIMPLE mode (no AI, just pattern matching)...")
    print("\n🧪 Test page: http://localhost:8000/test")
    print("📚 API docs: http://localhost:8000/docs")
    print("\nTry these injection attacks:")
    print("  - SQL: admin' OR '1'='1")
    print("  - XSS: <script>alert('XSS')</script>")
    print("  - XSS: <img src=x onerror=alert('XSS')>")
    print("\nPress Ctrl+C to stop\n")
    os.system("python main_simple.py")