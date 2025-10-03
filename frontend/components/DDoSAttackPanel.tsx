'use client'

import React, { useState, useEffect, useRef } from 'react'
import mermaid from 'mermaid'

interface AttackStatus {
  protection: any
  attack: any
  visualizations: {
    attack_flow: string
    mitigation: string
    statistics: string
  }
  explanation: any
}

export default function DDoSAttackPanel() {
  const [attacking, setAttacking] = useState(false)
  const [attackType, setAttackType] = useState('multi-vector')
  const [duration, setDuration] = useState(30)
  const [intensity, setIntensity] = useState(50)
  const [status, setStatus] = useState<AttackStatus | null>(null)
  const [loading, setLoading] = useState(false)
  
  const attackFlowRef = useRef<HTMLDivElement>(null)
  const mitigationRef = useRef<HTMLDivElement>(null)
  const statsRef = useRef<HTMLDivElement>(null)
  
  useEffect(() => {
    mermaid.initialize({
      startOnLoad: false,
      theme: 'dark',
      securityLevel: 'loose'
    })
  }, [])
  
  useEffect(() => {
    if (attacking) {
      const interval = setInterval(fetchStatus, 2000)
      return () => clearInterval(interval)
    }
  }, [attacking])
  
  useEffect(() => {
    if (status?.visualizations) {
      renderDiagrams()
    }
  }, [status?.visualizations])
  
  const renderDiagrams = async () => {
    if (status?.visualizations) {
      // Render attack flow
      if (attackFlowRef.current && status.visualizations.attack_flow) {
        await renderMermaid(attackFlowRef.current, status.visualizations.attack_flow, 'attack-flow')
      }
      
      // Render mitigation
      if (mitigationRef.current && status.visualizations.mitigation) {
        await renderMermaid(mitigationRef.current, status.visualizations.mitigation, 'mitigation')
      }
      
      // Render statistics
      if (statsRef.current && status.visualizations.statistics) {
        await renderMermaid(statsRef.current, status.visualizations.statistics, 'statistics')
      }
    }
  }
  
  const renderMermaid = async (container: HTMLElement, diagram: string, prefix: string) => {
    container.innerHTML = ''
    try {
      const id = `${prefix}-${Date.now()}`
      const { svg } = await mermaid.render(id, diagram)
      container.innerHTML = svg
    } catch (error) {
      console.error(`Failed to render ${prefix}:`, error)
      container.innerHTML = `<div class="text-red-400">Failed to render diagram</div>`
    }
  }
  
  const startAttack = async () => {
    setLoading(true)
    try {
      const response = await fetch('http://localhost:8000/api/ddos/start', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          type: attackType,
          duration,
          intensity
        })
      })
      
      if (response.ok) {
        setAttacking(true)
        fetchStatus()
      }
    } catch (error) {
      console.error('Failed to start attack:', error)
    } finally {
      setLoading(false)
    }
  }
  
  const stopAttack = async () => {
    setLoading(true)
    try {
      await fetch('http://localhost:8000/api/ddos/stop', { method: 'POST' })
      setAttacking(false)
      fetchStatus()
    } catch (error) {
      console.error('Failed to stop attack:', error)
    } finally {
      setLoading(false)
    }
  }
  
  const fetchStatus = async () => {
    try {
      const response = await fetch('http://localhost:8000/api/ddos/status')
      const data = await response.json()
      setStatus(data)
    } catch (error) {
      console.error('Failed to fetch status:', error)
    }
  }
  
  const resetProtection = async () => {
    try {
      await fetch('http://localhost:8000/api/ddos/reset', { method: 'POST' })
      fetchStatus()
    } catch (error) {
      console.error('Failed to reset protection:', error)
    }
  }
  
  return (
    <div className="bg-gray-900 rounded-lg p-6 space-y-6">
      {/* Attack Control Panel */}
      <div className="bg-gray-800 rounded-lg p-6">
        <h2 className="text-2xl font-bold text-white mb-4">🚨 DDoS Attack Simulator</h2>
        
        <div className="grid grid-cols-1 md:grid-cols-3 gap-4 mb-4">
          <div>
            <label className="block text-sm font-medium text-gray-300 mb-2">
              Attack Type
            </label>
            <select
              value={attackType}
              onChange={(e) => setAttackType(e.target.value)}
              disabled={attacking}
              className="w-full px-3 py-2 bg-gray-700 text-white rounded-lg focus:outline-none focus:ring-2 focus:ring-red-500"
            >
              <option value="volumetric">Volumetric Flood</option>
              <option value="slowloris">Slowloris</option>
              <option value="application">Application Layer</option>
              <option value="multi-vector">Multi-Vector (All)</option>
            </select>
          </div>
          
          <div>
            <label className="block text-sm font-medium text-gray-300 mb-2">
              Duration (seconds)
            </label>
            <input
              type="number"
              value={duration}
              onChange={(e) => setDuration(Number(e.target.value))}
              min={10}
              max={120}
              disabled={attacking}
              className="w-full px-3 py-2 bg-gray-700 text-white rounded-lg focus:outline-none focus:ring-2 focus:ring-red-500"
            />
          </div>
          
          <div>
            <label className="block text-sm font-medium text-gray-300 mb-2">
              Intensity (1-100)
            </label>
            <input
              type="number"
              value={intensity}
              onChange={(e) => setIntensity(Number(e.target.value))}
              min={1}
              max={100}
              disabled={attacking}
              className="w-full px-3 py-2 bg-gray-700 text-white rounded-lg focus:outline-none focus:ring-2 focus:ring-red-500"
            />
          </div>
        </div>
        
        <div className="flex gap-4">
          {!attacking ? (
            <button
              onClick={startAttack}
              disabled={loading}
              className="px-6 py-3 bg-red-600 text-white font-semibold rounded-lg hover:bg-red-700 disabled:opacity-50"
            >
              🔥 Start Attack
            </button>
          ) : (
            <button
              onClick={stopAttack}
              disabled={loading}
              className="px-6 py-3 bg-green-600 text-white font-semibold rounded-lg hover:bg-green-700 disabled:opacity-50"
            >
              ⛔ Stop Attack
            </button>
          )}
          
          <button
            onClick={resetProtection}
            className="px-6 py-3 bg-blue-600 text-white font-semibold rounded-lg hover:bg-blue-700"
          >
            🔄 Reset Protection
          </button>
        </div>
        
        {attacking && (
          <div className="mt-4 p-4 bg-red-900/20 border border-red-600 rounded-lg">
            <p className="text-red-400 font-semibold animate-pulse">
              ⚠️ Attack in Progress - Sending real traffic to server
            </p>
          </div>
        )}
      </div>
      
      {/* Status Display */}
      {status && (
        <>
          {/* Attack Statistics */}
          <div className="bg-gray-800 rounded-lg p-6">
            <h3 className="text-xl font-semibold text-white mb-4">📊 Attack Statistics</h3>
            
            <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
              <div className="bg-gray-700 rounded p-3">
                <div className="text-gray-400 text-sm">Total Requests</div>
                <div className="text-2xl font-bold text-white">
                  {status.attack?.total_requests || 0}
                </div>
              </div>
              
              <div className="bg-gray-700 rounded p-3">
                <div className="text-gray-400 text-sm">Blocked</div>
                <div className="text-2xl font-bold text-red-400">
                  {status.protection?.metrics?.blocked_requests || 0}
                </div>
              </div>
              
              <div className="bg-gray-700 rounded p-3">
                <div className="text-gray-400 text-sm">Current RPS</div>
                <div className="text-2xl font-bold text-yellow-400">
                  {status.protection?.current_rps?.toFixed(1) || 0}
                </div>
              </div>
              
              <div className="bg-gray-700 rounded p-3">
                <div className="text-gray-400 text-sm">Blocked IPs</div>
                <div className="text-2xl font-bold text-orange-400">
                  {status.protection?.blocked_count || 0}
                </div>
              </div>
            </div>
          </div>
          
          {/* Attack Flow Visualization */}
          <div className="bg-gray-800 rounded-lg p-6">
            <h3 className="text-xl font-semibold text-white mb-4">🔥 Attack Flow</h3>
            <div ref={attackFlowRef} className="overflow-auto"></div>
          </div>
          
          {/* Mitigation Flow */}
          <div className="bg-gray-800 rounded-lg p-6">
            <h3 className="text-xl font-semibold text-white mb-4">🛡️ Mitigation Strategy</h3>
            <div ref={mitigationRef} className="overflow-auto"></div>
          </div>
          
          {/* Statistics Diagram */}
          <div className="bg-gray-800 rounded-lg p-6">
            <h3 className="text-xl font-semibold text-white mb-4">📈 Traffic Analysis</h3>
            <div ref={statsRef} className="overflow-auto"></div>
          </div>
          
          {/* Attack Explanation */}
          {status.explanation && (
            <div className="bg-gray-800 rounded-lg p-6">
              <h3 className="text-xl font-semibold text-white mb-4">📖 Attack Analysis</h3>
              
              <div className="space-y-4">
                <div>
                  <h4 className="text-lg font-semibold text-blue-400 mb-2">
                    {status.explanation.attack_type} Attack
                  </h4>
                  <p className="text-gray-300">
                    {status.explanation.explanation?.description}
                  </p>
                </div>
                
                <div>
                  <h5 className="text-md font-semibold text-gray-400 mb-2">How it works:</h5>
                  <ul className="list-disc list-inside space-y-1">
                    {status.explanation.explanation?.how_it_works?.map((item: string, idx: number) => (
                      <li key={idx} className="text-gray-300">{item}</li>
                    ))}
                  </ul>
                </div>
                
                <div>
                  <h5 className="text-md font-semibold text-gray-400 mb-2">Mitigation Actions:</h5>
                  <ul className="list-disc list-inside space-y-1">
                    {status.explanation.mitigation?.actions_taken?.map((action: string, idx: number) => (
                      <li key={idx} className="text-green-400">{action}</li>
                    ))}
                  </ul>
                  <p className="text-gray-300 mt-2">
                    Effectiveness: <span className="text-green-400 font-semibold">
                      {status.explanation.mitigation?.effectiveness}
                    </span>
                  </p>
                </div>
                
                <div>
                  <h5 className="text-md font-semibold text-gray-400 mb-2">Recommendations:</h5>
                  <ul className="list-disc list-inside space-y-1">
                    {status.explanation.recommendations?.map((rec: string, idx: number) => (
                      <li key={idx} className="text-blue-300">{rec}</li>
                    ))}
                  </ul>
                </div>
              </div>
            </div>
          )}
        </>
      )}
    </div>
  )
}