"use client";

import { useEffect, useState, useCallback } from 'react';
import PacketStream from '@/components/PacketStream';
import ThreatMonitor from '@/components/ThreatMonitor';
import MetricsGrid from '@/components/MetricsGrid';
import ActivityLog from '@/components/ActivityLog';
import ControlPanel from '@/components/ControlPanel';
import Header from '@/components/Header';

interface Packet {
  id: string;
  timestamp: string;
  src_ip: string;
  dst_ip: string;
  src_port: number;
  dst_port: number;
  protocol: string;
  size: number;
  threat_level: 'safe' | 'medium' | 'high' | 'critical';
  threats?: Array<{
    type: string;
    pattern: string;
    severity: string;
  }>;
}

interface LogEntry {
  id: string;
  timestamp: Date;
  message: string;
  type: 'info' | 'warning' | 'error' | 'success';
}

let packetCounter = 0;
let logCounter = 0;

export default function Dashboard() {
  const [packets, setPackets] = useState<Packet[]>([]);
  const [logs, setLogs] = useState<LogEntry[]>([]);
  const [isCapturing, setIsCapturing] = useState(false);
  const [eventSource, setEventSource] = useState<WebSocket | null>(null);
  const [metrics, setMetrics] = useState({
    totalPackets: 0,
    threatCount: 0,
    activeSessions: 0,
    bandwidth: 0,
    responseTime: 0,
    criticalAlerts: 0
  });
  const [threatData, setThreatData] = useState({
    xss: 0,
    sql: 0,
    dos: 0,
    csrf: 0,
    scan: 0
  });

  const addLog = useCallback((message: string, type: LogEntry['type'] = 'info') => {
    const newLog: LogEntry = {
      id: `log-${Date.now()}-${++logCounter}`,
      timestamp: new Date(),
      message,
      type
    };
    setLogs(prev => [newLog, ...prev].slice(0, 50));
  }, []);

  const processPacket = useCallback((packet: Packet) => {
    setPackets(prev => [packet, ...prev].slice(0, 20));
    
    setMetrics(prev => ({
      ...prev,
      totalPackets: prev.totalPackets + 1,
      threatCount: packet.threat_level !== 'safe' ? prev.threatCount + 1 : prev.threatCount,
      criticalAlerts: packet.threat_level === 'critical' ? prev.criticalAlerts + 1 : prev.criticalAlerts
    }));

    if (packet.threat_level !== 'safe' && packet.threats && packet.threats[0]) {
      const threatType = packet.threats[0].type.toLowerCase();
      const typeMap: { [key: string]: keyof typeof threatData } = {
        'xss': 'xss',
        'sql injection': 'sql',
        'dos': 'dos',
        'csrf': 'csrf',
        'port scan': 'scan'
      };
      
      const mappedType = typeMap[threatType] || 'scan';
      setThreatData(prev => ({
        ...prev,
        [mappedType]: Math.min(100, prev[mappedType] + 5)
      }));

      addLog(
        `Threat detected: ${packet.threats[0].type} - ${packet.threats[0].pattern}`,
        packet.threat_level === 'critical' ? 'error' : 'warning'
      );
    }
  }, [addLog]);

  const startCapture = async () => {
    console.log('startCapture called');
    
    // Don't start if already capturing
    if (isCapturing) {
      console.log('Already capturing, skipping');
      return;
    }
    
    try {
      addLog('Attempting to connect to WebSocket...', 'info');
      
      // Connect to WebSocket for real-time packet streaming
      const ws = new WebSocket('ws://localhost:8000/ws');
      
      ws.onopen = () => {
        console.log('WebSocket connected');
        setIsCapturing(true);
        addLog(`Connected to packet monitor - watching port 8080`, 'success');
      };
      
      ws.onmessage = (event) => {
        const packet = JSON.parse(event.data);
        processPacket({
          id: packet.id || `PKT-${Date.now()}-${++packetCounter}`,
          timestamp: packet.timestamp,
          src_ip: packet.src_ip,
          dst_ip: packet.dst_ip,
          src_port: packet.src_port,
          dst_port: packet.dst_port,
          protocol: packet.protocol,
          size: packet.size,
          threat_level: packet.threat_level,
          threats: packet.threats
        });
      };
      
      ws.onerror = (error) => {
        console.error('WebSocket error:', error);
        addLog('WebSocket connection error - is the backend running on port 8000?', 'error');
        setIsCapturing(false);
        
        // Fallback to simulation
        addLog('Starting simulation mode as fallback', 'warning');
        simulatePackets();
      };
      
      ws.onclose = () => {
        console.log('WebSocket closed');
        addLog('Disconnected from monitor', 'warning');
        setIsCapturing(false);
      };
      
      setEventSource(ws);
    } catch (error) {
      console.error('Failed to connect:', error);
      addLog('Failed to connect to monitor - starting simulation mode', 'error');
      
      // Start simulation as fallback
      setIsCapturing(true);
      simulatePackets();
    }
  };

  const stopCapture = async () => {
    setIsCapturing(false);
    if (eventSource) {
      eventSource.close();
      setEventSource(null);
    }
    addLog('Capture stopped', 'info');
  };

  const _simulateWithBackend = () => {
    const testInputs = [
      { search: "normal search term" },
      { search: "<script>alert('XSS')</script>" },
      { username: "admin' OR '1'='1", password: "password" },
      { comment: "'; DROP TABLE users; --" },
      { search: "javascript:alert(1)" },
      { email: "test@test.com", comment: "onclick=alert(1)" }
    ];

    let index = 0;
    const interval = setInterval(async () => {
      if (!isCapturing) {
        clearInterval(interval);
        return;
      }

      const input = testInputs[index % testInputs.length];
      index++;

      try {
        const response = await fetch('http://localhost:8000/api/test/analyze', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify(input)
        });

        if (response.ok) {
          const analysis = await response.json();
          const packet: Packet = {
            id: `PKT-${Date.now()}-${++packetCounter}-${index}`,
            timestamp: analysis.timestamp || new Date().toISOString(),
            src_ip: `192.168.1.${Math.floor(Math.random() * 255)}`,
            dst_ip: '10.0.0.1',
            src_port: Math.floor(Math.random() * 65535),
            dst_port: 80,
            protocol: 'HTTP',
            size: Math.floor(Math.random() * 1500) + 100,
            threat_level: analysis.threat_level || 'safe',
            threats: analysis.threats
          };
          processPacket(packet);
        }
      } catch (error) {
        console.error('Failed to analyze:', error);
      }
    }, Math.random() * 2000 + 1000);

    return () => clearInterval(interval);
  };

  const simulatePackets = () => {
    console.log('Starting packet simulation');
    setIsCapturing(true);
    
    const ips = ['192.168.1.100', '10.0.0.50', '172.16.0.1', '8.8.8.8', '1.1.1.1'];
    const ports = [80, 443, 22, 3306, 8080];
    const protocols = ['TCP', 'UDP', 'HTTP', 'HTTPS'];
    const threatLevels: Packet['threat_level'][] = ['safe', 'safe', 'safe', 'medium', 'high', 'critical'];
    const threats = [
      { type: 'XSS', pattern: '<script>alert(1)</script>', severity: 'high' },
      { type: 'SQL Injection', pattern: "' OR '1'='1", severity: 'critical' },
      { type: 'Port Scan', pattern: 'Multiple port attempts', severity: 'medium' },
      { type: 'DoS', pattern: 'Excessive requests', severity: 'high' },
      { type: 'CSRF', pattern: 'Cross-site request', severity: 'medium' }
    ];

    const interval = setInterval(() => {
      const packet: Packet = {
        id: `PKT-${Date.now()}-${++packetCounter}-sim`,
        timestamp: new Date().toISOString(),
        src_ip: ips[Math.floor(Math.random() * ips.length)],
        dst_ip: ips[Math.floor(Math.random() * ips.length)],
        src_port: ports[Math.floor(Math.random() * ports.length)],
        dst_port: ports[Math.floor(Math.random() * ports.length)],
        protocol: protocols[Math.floor(Math.random() * protocols.length)],
        size: Math.floor(Math.random() * 1500) + 100,
        threat_level: threatLevels[Math.floor(Math.random() * threatLevels.length)]
      };

      if (packet.threat_level !== 'safe') {
        packet.threats = [threats[Math.floor(Math.random() * threats.length)]];
      }

      processPacket(packet);

      setMetrics(prev => ({
        ...prev,
        bandwidth: Math.random() * 10,
        activeSessions: Math.floor(Math.random() * 50) + 10,
        responseTime: Math.floor(Math.random() * 100) + 20
      }));
    }, 1000);

    // Store interval ID for cleanup
    setTimeout(() => {
      if (!isCapturing) clearInterval(interval);
    }, 100);
  };

  const searchPackets = async (query: string) => {
    try {
      // Send the query as a simulated attack to see if it contains threats
      const response = await fetch('http://localhost:8000/api/simulate', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ data: query })
      });
      
      if (response.ok) {
        const packet = await response.json();
        addLog(`Simulated packet sent: "${query}"`, 'info');
        if (packet.threat_level !== 'safe') {
          addLog(`Threat detected: ${packet.threat_level} - ${packet.threats[0]?.type}`, 'warning');
        }
      }
    } catch (error) {
      console.error('Simulation failed:', error);
      addLog('Failed to send simulated packet', 'error');
    }
  };

  useEffect(() => {
    addLog('Dashboard initialized', 'success');
    return () => {
      if (eventSource) {
        eventSource.close();
      }
    };
  // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  return (
    <div className="min-h-screen bg-black">
      <div className="relative">
        <div className="absolute inset-0 bg-grid-white/[0.01] pointer-events-none" />
        <div className="relative">
          <Header isCapturing={isCapturing} />
          
          <div className="container mx-auto px-4 py-6">
            <ControlPanel 
              onStartCapture={startCapture}
              onStopCapture={stopCapture}
              onSearch={searchPackets}
              isCapturing={isCapturing}
            />
            
            <MetricsGrid metrics={metrics} />
            
            <div className="grid grid-cols-1 lg:grid-cols-3 gap-6 mb-6">
              <div className="lg:col-span-2">
                <PacketStream packets={packets} />
              </div>
              <div>
                <ThreatMonitor threatData={threatData} packets={packets} />
              </div>
            </div>
            
            <ActivityLog logs={logs} />
          </div>
        </div>
      </div>
    </div>
  );
}