"""
Test if attack report queries work
"""
import asyncio
import aiohttp
import json

async def test_report_queries():
    """Test various report queries"""
    base_url = "http://localhost:8000"
    
    print("=" * 60)
    print("🧪 Testing Attack Report Queries")
    print("=" * 60)
    
    async with aiohttp.ClientSession() as session:
        # Test queries
        queries = [
            "show attack reports",
            "show recent reports", 
            "what attacks happened today",
            "get attack statistics",
            "show the latest attack",
            "how many attacks were there"
        ]
        
        for query in queries:
            print(f"\n📝 Query: '{query}'")
            
            try:
                payload = {"query": query}
                async with session.post(f"{base_url}/api/query", json=payload) as resp:
                    if resp.status == 200:
                        result = await resp.json()
                        
                        if result.get("success"):
                            print(f"   ✅ Success!")
                            
                            # Check what data was returned
                            data = result.get("data", {})
                            
                            if "reports" in data:
                                count = data.get("count", 0)
                                print(f"   Found {count} reports")
                                
                                # Show first report if available
                                if count > 0 and data["reports"]:
                                    first_report = data["reports"][0]
                                    print(f"   Latest: {first_report.get('id', 'No ID')}")
                                    
                            elif "report" in data:
                                report = data.get("report")
                                if report:
                                    print(f"   Report ID: {report.get('id', 'No ID')}")
                                else:
                                    print("   No report found")
                                    
                            elif "statistics" in data:
                                stats = data.get("statistics", {})
                                print(f"   Total attacks: {stats.get('total_attacks', 0)}")
                                
                            elif "total" in data:
                                print(f"   Total attacks: {data.get('total', 0)}")
                                
                            # Show message
                            if data.get("message"):
                                print(f"   Message: {data['message']}")
                                
                        else:
                            print(f"   ❌ Query failed: {result.get('error', 'Unknown error')}")
                    else:
                        print(f"   ❌ HTTP error: {resp.status}")
                        
            except Exception as e:
                print(f"   ❌ Error: {e}")
        
        # Test direct API endpoints
        print("\n" + "=" * 60)
        print("📊 Testing Direct API Endpoints")
        print("=" * 60)
        
        endpoints = [
            "/api/reports",
            "/api/reports/stats",
            "/api/reports/latest"
        ]
        
        for endpoint in endpoints:
            print(f"\n🔗 {endpoint}")
            
            try:
                async with session.get(f"{base_url}{endpoint}") as resp:
                    if resp.status == 200:
                        data = await resp.json()
                        
                        if "reports" in data:
                            print(f"   Reports: {data.get('count', 0)}")
                        elif "total_attacks" in data:
                            print(f"   Total attacks: {data['total_attacks']}")
                        elif "id" in data:
                            print(f"   Report ID: {data['id']}")
                        else:
                            print(f"   Response: {json.dumps(data, indent=2)[:200]}")
                    else:
                        print(f"   ❌ HTTP error: {resp.status}")
                        
            except Exception as e:
                print(f"   ❌ Error: {e}")

if __name__ == "__main__":
    print("Make sure backend is running: python main_ws.py")
    print("Starting test...\n")
    asyncio.run(test_report_queries())