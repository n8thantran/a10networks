'use client'

import React, { useState, useEffect } from 'react'

interface AttackStats {
  total_packets: number
  total_bytes: number
  unique_sources: number
  packets_per_second: number
  bandwidth_mbps: number
  top_protocols: [string, number][]
  top_ports: [number, number][]
  attack_vector: string
  severity: string
}

interface AttackPacket {
  id: string
  src_ip: string
  dst_ip: string
  src_port: number
  dst_port: number
  protocol: string
  size: number
  threat_level: string
  attack_type: string
}

export default function AttackSimulator() {
  const [isAttacking, setIsAttacking] = useState(false)
  const [targetIp, setTargetIp] = useState('10.0.0.1')
  const [targetPort, setTargetPort] = useState('')
  const [waveSize, setWaveSize] = useState(100)
  const [attackStats, setAttackStats] = useState<AttackStats | null>(null)
  const [recentPackets, setRecentPackets] = useState<AttackPacket[]>([])
  const [totalAttacks, setTotalAttacks] = useState(0)
  const [animatePackets, setAnimatePackets] = useState(false)

  const launchDDoS = async () => {
    setIsAttacking(true)
    setAnimatePackets(true)

    try {
      const response = await fetch('http://localhost:8000/api/attack/ddos', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({
          target_ip: targetIp,
          target_port: targetPort ? parseInt(targetPort) : null,
          wave_size: waveSize,
          mixed_attack: true
        })
      })

      const data = await response.json()
      
      if (data.success) {
        setAttackStats(data.statistics)
        setRecentPackets(data.packets)
        setTotalAttacks(prev => prev + data.packets_generated)
        
        // Animate for 3 seconds
        setTimeout(() => {
          setAnimatePackets(false)
        }, 3000)
      }
    } catch (error) {
      console.error('Attack simulation failed:', error)
    } finally {
      setIsAttacking(false)
    }
  }

  const formatBytes = (bytes: number) => {
    if (bytes < 1024) return bytes + ' B'
    if (bytes < 1048576) return (bytes / 1024).toFixed(2) + ' KB'
    if (bytes < 1073741824) return (bytes / 1048576).toFixed(2) + ' MB'
    return (bytes / 1073741824).toFixed(2) + ' GB'
  }

  return (
    <div className="bg-gray-900 rounded-lg p-6 border border-red-600/30">
      <div className="mb-6">
        <div className="flex items-center justify-between mb-4">
          <h2 className="text-2xl font-bold text-red-500 flex items-center gap-2">
            <span className="text-3xl">⚠️</span>
            DDoS Attack Simulator
            <span className="text-xs text-gray-400 ml-2">(Educational Only)</span>
          </h2>
          {attackStats && (
            <div className="text-right">
              <span className="text-xs text-gray-500">Total Attacks Sent</span>
              <div className="text-2xl font-bold text-red-400">{totalAttacks.toLocaleString()}</div>
            </div>
          )}
        </div>

        <div className="grid grid-cols-1 md:grid-cols-4 gap-4 mb-4">
          <div>
            <label className="block text-sm font-medium text-gray-400 mb-1">Target IP</label>
            <input
              type="text"
              value={targetIp}
              onChange={(e) => setTargetIp(e.target.value)}
              className="w-full px-3 py-2 bg-gray-800 text-white rounded border border-gray-700 focus:border-red-500 focus:outline-none"
              placeholder="10.0.0.1"
            />
          </div>
          
          <div>
            <label className="block text-sm font-medium text-gray-400 mb-1">Target Port (Optional)</label>
            <input
              type="text"
              value={targetPort}
              onChange={(e) => setTargetPort(e.target.value)}
              className="w-full px-3 py-2 bg-gray-800 text-white rounded border border-gray-700 focus:border-red-500 focus:outline-none"
              placeholder="80"
            />
          </div>
          
          <div>
            <label className="block text-sm font-medium text-gray-400 mb-1">Wave Size</label>
            <select
              value={waveSize}
              onChange={(e) => setWaveSize(parseInt(e.target.value))}
              className="w-full px-3 py-2 bg-gray-800 text-white rounded border border-gray-700 focus:border-red-500 focus:outline-none"
            >
              <option value="50">50 packets</option>
              <option value="100">100 packets</option>
              <option value="200">200 packets</option>
              <option value="500">500 packets</option>
              <option value="1000">1000 packets</option>
            </select>
          </div>
          
          <div className="flex items-end">
            <button
              onClick={launchDDoS}
              disabled={isAttacking}
              className={`w-full px-6 py-2 font-bold rounded transition-all transform ${
                isAttacking 
                  ? 'bg-gray-700 text-gray-400 cursor-not-allowed'
                  : 'bg-gradient-to-r from-red-600 to-red-700 text-white hover:from-red-700 hover:to-red-800 hover:scale-105 animate-pulse'
              }`}
            >
              {isAttacking ? '🔥 ATTACKING...' : '💀 LAUNCH DDOS'}
            </button>
          </div>
        </div>
      </div>

      {attackStats && (
        <>
          <div className="grid grid-cols-2 md:grid-cols-4 gap-4 mb-6">
            <div className="bg-gray-800/50 p-3 rounded border border-red-600/20">
              <div className="text-xs text-gray-500 mb-1">Total Packets</div>
              <div className="text-xl font-bold text-red-400">{attackStats.total_packets}</div>
            </div>
            
            <div className="bg-gray-800/50 p-3 rounded border border-red-600/20">
              <div className="text-xs text-gray-500 mb-1">Bandwidth</div>
              <div className="text-xl font-bold text-orange-400">{attackStats.bandwidth_mbps.toFixed(2)} Mbps</div>
            </div>
            
            <div className="bg-gray-800/50 p-3 rounded border border-red-600/20">
              <div className="text-xs text-gray-500 mb-1">Unique Sources</div>
              <div className="text-xl font-bold text-yellow-400">{attackStats.unique_sources}</div>
            </div>
            
            <div className="bg-gray-800/50 p-3 rounded border border-red-600/20">
              <div className="text-xs text-gray-500 mb-1">Attack Vector</div>
              <div className="text-xl font-bold text-purple-400">{attackStats.attack_vector}</div>
            </div>
          </div>

          <div className="grid grid-cols-1 md:grid-cols-2 gap-4 mb-6">
            <div className="bg-gray-800/50 p-4 rounded border border-red-600/20">
              <h3 className="text-sm font-semibold text-gray-400 mb-2">Top Protocols</h3>
              <div className="space-y-1">
                {attackStats.top_protocols.map(([protocol, count], idx) => (
                  <div key={idx} className="flex justify-between items-center">
                    <span className="text-gray-300">{protocol}</span>
                    <div className="flex items-center gap-2">
                      <div className="w-24 bg-gray-700 rounded-full h-2">
                        <div 
                          className="bg-gradient-to-r from-red-500 to-orange-500 h-2 rounded-full"
                          style={{ width: `${(count / attackStats.total_packets) * 100}%` }}
                        />
                      </div>
                      <span className="text-gray-400 text-xs">{count}</span>
                    </div>
                  </div>
                ))}
              </div>
            </div>
            
            <div className="bg-gray-800/50 p-4 rounded border border-red-600/20">
              <h3 className="text-sm font-semibold text-gray-400 mb-2">Targeted Ports</h3>
              <div className="space-y-1">
                {attackStats.top_ports.map(([port, count], idx) => (
                  <div key={idx} className="flex justify-between items-center">
                    <span className="text-gray-300">Port {port}</span>
                    <div className="flex items-center gap-2">
                      <div className="w-24 bg-gray-700 rounded-full h-2">
                        <div 
                          className="bg-gradient-to-r from-purple-500 to-pink-500 h-2 rounded-full"
                          style={{ width: `${(count / attackStats.total_packets) * 100}%` }}
                        />
                      </div>
                      <span className="text-gray-400 text-xs">{count}</span>
                    </div>
                  </div>
                ))}
              </div>
            </div>
          </div>

          <div className="bg-gray-800/50 p-4 rounded border border-red-600/20">
            <h3 className="text-sm font-semibold text-gray-400 mb-2">Attack Packets Sample</h3>
            <div className="overflow-x-auto">
              <table className="w-full text-xs">
                <thead>
                  <tr className="text-gray-500">
                    <th className="text-left p-2">Source IP</th>
                    <th className="text-left p-2">Source Port</th>
                    <th className="text-left p-2">Target Port</th>
                    <th className="text-left p-2">Protocol</th>
                    <th className="text-left p-2">Size</th>
                    <th className="text-left p-2">Type</th>
                  </tr>
                </thead>
                <tbody>
                  {recentPackets.map((packet, idx) => (
                    <tr 
                      key={packet.id} 
                      className={`border-t border-gray-700/50 text-gray-300 ${
                        animatePackets ? 'animate-pulse' : ''
                      }`}
                      style={{
                        animationDelay: `${idx * 100}ms`
                      }}
                    >
                      <td className="p-2 font-mono">{packet.src_ip}</td>
                      <td className="p-2">{packet.src_port}</td>
                      <td className="p-2">{packet.dst_port}</td>
                      <td className="p-2">
                        <span className={`px-2 py-1 rounded text-xs ${
                          packet.protocol === 'SYN' ? 'bg-red-900/50 text-red-400' :
                          packet.protocol === 'UDP' ? 'bg-blue-900/50 text-blue-400' :
                          packet.protocol === 'HTTP' ? 'bg-green-900/50 text-green-400' :
                          packet.protocol === 'DNS' ? 'bg-purple-900/50 text-purple-400' :
                          'bg-gray-700 text-gray-400'
                        }`}>
                          {packet.protocol}
                        </span>
                      </td>
                      <td className="p-2">{formatBytes(packet.size)}</td>
                      <td className="p-2">
                        <span className="text-red-400 font-semibold">{packet.attack_type}</span>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </div>
        </>
      )}

      {animatePackets && (
        <div className="fixed inset-0 pointer-events-none z-50">
          {[...Array(20)].map((_, i) => (
            <div
              key={i}
              className="absolute w-2 h-2 bg-red-500 rounded-full animate-ping"
              style={{
                left: `${Math.random() * 100}%`,
                top: `${Math.random() * 100}%`,
                animationDelay: `${Math.random() * 2}s`,
                animationDuration: `${1 + Math.random()}s`
              }}
            />
          ))}
        </div>
      )}
    </div>
  )
}