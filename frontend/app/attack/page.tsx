"use client";

import { useState } from 'react';

export default function AttackPanel() {
  const [packetCount, setPacketCount] = useState(0);
  const [logs, setLogs] = useState<string[]>(['Ready to send attacks...']);
  const [isConnected, setIsConnected] = useState(false);
  const [autoAttackInterval, setAutoAttackInterval] = useState<NodeJS.Timeout | null>(null);

  const addLog = (message: string, type: 'success' | 'error' = 'success') => {
    const time = new Date().toLocaleTimeString();
    const log = `[${time}] ${message}`;
    setLogs(prev => [log, ...prev].slice(0, 30));
  };

  const sendAttack = async (payload: string) => {
    try {
      setPacketCount(prev => prev + 1);
      
      const response = await fetch('http://localhost:8000/api/simulate', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({ data: payload })
      });

      if (response.ok) {
        const result = await response.json();
        const threatLevel = result.threat_level || 'unknown';
        addLog(`Sent: "${payload.substring(0, 40)}..." [${threatLevel.toUpperCase()}]`, 
               threatLevel === 'safe' ? 'success' : 'error');
        setIsConnected(true);
      } else {
        addLog(`Failed to send: ${payload}`, 'error');
        setIsConnected(false);
      }
    } catch (error) {
      addLog('Error: Backend not responding', 'error');
      setIsConnected(false);
    }
  };

  const sendBurst = async () => {
    const payloads = [
      'Normal search query',
      '<script>alert(1)</script>',
      "admin' OR '1'='1",
      'iPhone 15 Pro',
      "'; DROP TABLE users--",
      'user@example.com',
      '<img src=x onerror=alert(1)>',
      'Great product!',
      "admin'--",
      'laptop gaming'
    ];
    
    for (let payload of payloads) {
      await sendAttack(payload);
      await new Promise(r => setTimeout(r, 200));
    }
  };

  const sendRapidFire = async () => {
    for (let i = 0; i < 50; i++) {
      const attacks = [
        `<script>alert(${i})</script>`,
        `admin${i}' OR '1'='1`,
        `search_${i}`
      ];
      const payload = attacks[i % attacks.length];
      sendAttack(payload);
      await new Promise(r => setTimeout(r, 100));
    }
  };

  const startAutoAttack = () => {
    if (autoAttackInterval) return;
    
    const attacks = [
      '<script>alert("XSS")</script>',
      "admin' OR '1'='1'--",
      '<img src=x onerror=alert(1)>',
      "'; DROP TABLE users; --",
      'javascript:alert(1)',
      '../../etc/passwd',
      'Normal traffic',
      'SELECT * FROM users'
    ];
    
    let index = 0;
    const interval = setInterval(() => {
      sendAttack(attacks[index % attacks.length]);
      index++;
    }, 1000);
    
    setAutoAttackInterval(interval);
    addLog('Auto attack started (1/sec)', 'success');
  };

  const stopAutoAttack = () => {
    if (autoAttackInterval) {
      clearInterval(autoAttackInterval);
      setAutoAttackInterval(null);
      addLog('Auto attack stopped', 'error');
    }
  };

  const sendStealth = async () => {
    const sequence = [
      'admin',
      "admin'",
      "admin' O",
      "admin' OR",
      "admin' OR '",
      "admin' OR '1",
      "admin' OR '1'",
      "admin' OR '1'=",
      "admin' OR '1'='",
      "admin' OR '1'='1",
      "admin' OR '1'='1'"
    ];
    
    for (let part of sequence) {
      await sendAttack(part);
      await new Promise(r => setTimeout(r, 2000));
    }
  };

  return (
    <div className="min-h-screen bg-black text-green-500 p-6">
      <div className="max-w-7xl mx-auto">
        <h1 className="text-4xl font-bold text-center mb-8 text-green-400">
          🔥 NETSENTINEL ATTACK PANEL 🔥
        </h1>

        <div className={`text-center p-4 border-2 mb-6 ${isConnected ? 'border-green-500 text-green-500' : 'border-red-500 text-red-500'}`}>
          Status: {isConnected ? 'CONNECTED' : 'DISCONNECTED'} | 
          Packets Sent: <span className="text-yellow-500 font-bold">{packetCount}</span>
        </div>

        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6 mb-8">
          {/* SQL Injection */}
          <div className="bg-gray-900 border border-gray-700 p-4 rounded">
            <h3 className="text-yellow-500 font-bold mb-4">SQL INJECTION</h3>
            <div className="space-y-2">
              <button 
                onClick={() => sendAttack("admin' OR '1'='1'--")}
                className="w-full px-3 py-2 bg-black border border-red-500 text-red-500 hover:bg-red-500 hover:text-white transition-all"
              >
                Basic Bypass
              </button>
              <button 
                onClick={() => sendAttack("' OR '1'='1")}
                className="w-full px-3 py-2 bg-black border border-red-500 text-red-500 hover:bg-red-500 hover:text-white transition-all"
              >
                Classic OR 1=1
              </button>
              <button 
                onClick={() => sendAttack("admin'--")}
                className="w-full px-3 py-2 bg-black border border-red-500 text-red-500 hover:bg-red-500 hover:text-white transition-all"
              >
                Admin Comment
              </button>
              <button 
                onClick={() => sendAttack("'; DROP TABLE users; --")}
                className="w-full px-3 py-2 bg-black border border-red-500 text-red-500 hover:bg-red-500 hover:text-white transition-all"
              >
                Drop Table
              </button>
              <button 
                onClick={() => sendAttack("1' UNION SELECT * FROM users--")}
                className="w-full px-3 py-2 bg-black border border-red-500 text-red-500 hover:bg-red-500 hover:text-white transition-all"
              >
                Union Select
              </button>
              <button 
                onClick={() => sendAttack("' OR 'a'='a")}
                className="w-full px-3 py-2 bg-black border border-red-500 text-red-500 hover:bg-red-500 hover:text-white transition-all"
              >
                OR a=a
              </button>
            </div>
          </div>

          {/* XSS Attacks */}
          <div className="bg-gray-900 border border-gray-700 p-4 rounded">
            <h3 className="text-yellow-500 font-bold mb-4">XSS ATTACKS</h3>
            <div className="space-y-2">
              <button 
                onClick={() => sendAttack("<script>alert('XSS')</script>")}
                className="w-full px-3 py-2 bg-black border border-red-500 text-red-500 hover:bg-red-500 hover:text-white transition-all"
              >
                Script Alert
              </button>
              <button 
                onClick={() => sendAttack("<img src=x onerror=alert(1)>")}
                className="w-full px-3 py-2 bg-black border border-red-500 text-red-500 hover:bg-red-500 hover:text-white transition-all"
              >
                IMG Onerror
              </button>
              <button 
                onClick={() => sendAttack("<svg onload=alert(1)>")}
                className="w-full px-3 py-2 bg-black border border-red-500 text-red-500 hover:bg-red-500 hover:text-white transition-all"
              >
                SVG Onload
              </button>
              <button 
                onClick={() => sendAttack("javascript:alert(document.cookie)")}
                className="w-full px-3 py-2 bg-black border border-red-500 text-red-500 hover:bg-red-500 hover:text-white transition-all"
              >
                JS Protocol
              </button>
              <button 
                onClick={() => sendAttack("<iframe src=javascript:alert(1)>")}
                className="w-full px-3 py-2 bg-black border border-red-500 text-red-500 hover:bg-red-500 hover:text-white transition-all"
              >
                Iframe XSS
              </button>
              <button 
                onClick={() => sendAttack("<body onload=alert(1)>")}
                className="w-full px-3 py-2 bg-black border border-red-500 text-red-500 hover:bg-red-500 hover:text-white transition-all"
              >
                Body Onload
              </button>
            </div>
          </div>

          {/* Normal Traffic */}
          <div className="bg-gray-900 border border-gray-700 p-4 rounded">
            <h3 className="text-yellow-500 font-bold mb-4">NORMAL TRAFFIC</h3>
            <div className="space-y-2">
              <button 
                onClick={() => sendAttack("iPhone 15 Pro Max")}
                className="w-full px-3 py-2 bg-black border border-green-500 text-green-500 hover:bg-green-500 hover:text-black transition-all"
              >
                Search iPhone
              </button>
              <button 
                onClick={() => sendAttack("laptop gaming RTX 4090")}
                className="w-full px-3 py-2 bg-black border border-green-500 text-green-500 hover:bg-green-500 hover:text-black transition-all"
              >
                Search Laptop
              </button>
              <button 
                onClick={() => sendAttack("user@example.com")}
                className="w-full px-3 py-2 bg-black border border-green-500 text-green-500 hover:bg-green-500 hover:text-black transition-all"
              >
                Normal Email
              </button>
              <button 
                onClick={() => sendAttack("John Smith")}
                className="w-full px-3 py-2 bg-black border border-green-500 text-green-500 hover:bg-green-500 hover:text-black transition-all"
              >
                Normal Name
              </button>
              <button 
                onClick={() => sendAttack("Great product 5 stars")}
                className="w-full px-3 py-2 bg-black border border-green-500 text-green-500 hover:bg-green-500 hover:text-black transition-all"
              >
                Normal Review
              </button>
              <button 
                onClick={() => sendAttack("password123")}
                className="w-full px-3 py-2 bg-black border border-green-500 text-green-500 hover:bg-green-500 hover:text-black transition-all"
              >
                Normal Password
              </button>
            </div>
          </div>

          {/* Automated */}
          <div className="bg-gray-900 border border-gray-700 p-4 rounded">
            <h3 className="text-yellow-500 font-bold mb-4">AUTOMATED</h3>
            <div className="space-y-2">
              <button 
                onClick={sendBurst}
                className="w-full px-3 py-2 bg-black border border-purple-500 text-purple-500 hover:bg-purple-500 hover:text-white transition-all"
              >
                🚀 Send 10 Mixed
              </button>
              <button 
                onClick={sendRapidFire}
                className="w-full px-3 py-2 bg-black border border-purple-500 text-purple-500 hover:bg-purple-500 hover:text-white transition-all"
              >
                ⚡ Rapid Fire (50)
              </button>
              <button 
                onClick={startAutoAttack}
                className="w-full px-3 py-2 bg-black border border-purple-500 text-purple-500 hover:bg-purple-500 hover:text-white transition-all"
              >
                ▶️ Start Auto Attack
              </button>
              <button 
                onClick={stopAutoAttack}
                className="w-full px-3 py-2 bg-black border border-purple-500 text-purple-500 hover:bg-purple-500 hover:text-white transition-all"
              >
                ⏹️ Stop Auto Attack
              </button>
              <button 
                onClick={sendStealth}
                className="w-full px-3 py-2 bg-black border border-purple-500 text-purple-500 hover:bg-purple-500 hover:text-white transition-all"
              >
                🥷 Stealth Attack
              </button>
              <button 
                onClick={() => setLogs(['Log cleared'])}
                className="w-full px-3 py-2 bg-black border border-yellow-500 text-yellow-500 hover:bg-yellow-500 hover:text-black transition-all"
              >
                🗑️ Clear Log
              </button>
            </div>
          </div>
        </div>

        {/* Log */}
        <div className="bg-gray-900 border border-gray-700 p-4 rounded">
          <h3 className="text-yellow-500 font-bold mb-2">ACTIVITY LOG</h3>
          <div className="bg-black p-3 h-48 overflow-y-auto font-mono text-xs">
            {logs.map((log, index) => (
              <div key={index} className={log.includes('Error') || log.includes('Failed') ? 'text-red-500' : 'text-green-500'}>
                {log}
              </div>
            ))}
          </div>
        </div>

        {/* Instructions */}
        <div className="mt-6 text-center text-gray-500 text-sm">
          <p>Make sure backend is running on port 8000 (python main_ws.py)</p>
          <p>Dashboard should be open at localhost:3000/dashboard with capture started</p>
        </div>
      </div>
    </div>
  );
}