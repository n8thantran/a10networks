'use client'

import React, { useState, useEffect } from 'react'
import MermaidDiagram from './MermaidDiagram'

interface AttackReport {
  id: string
  created_at: string
  attack_summary: {
    type: string
    start_time: string
    end_time: string
    duration_seconds: number
    status: string
    severity: string
  }
  traffic_statistics: {
    total_requests: number
    successful_requests: number
    failed_requests: number
    blocked_requests: number
    bytes_sent: number
    peak_rps: number
    average_rps: number
  }
  mitigation_actions: {
    effectiveness_percentage: number
    ips_blocked: string[]
    response_time_seconds: number
  }
  recommendations: string[]
  visualizations?: {
    attack_flow?: string
    mitigation_flow?: string
    statistics?: string
  }
}

export default function AttackReportViewer() {
  const [reports, setReports] = useState<AttackReport[]>([])
  const [selectedReport, setSelectedReport] = useState<AttackReport | null>(null)
  const [loading, setLoading] = useState(false)
  const [autoDetected, setAutoDetected] = useState<string | null>(null)

  useEffect(() => {
    fetchReports()
    
    // Set up WebSocket listener for auto-detection alerts
    const ws = new WebSocket('ws://localhost:8000/ws')
    
    ws.onmessage = (event) => {
      try {
        const data = JSON.parse(event.data)
        if (data.type === 'attack_alert') {
          setAutoDetected(data.attack_id)
          fetchReports() // Refresh reports
          
          // Show notification
          showNotification(data.message, data.severity)
        }
      } catch (error) {
        console.error('Failed to parse WebSocket message:', error)
      }
    }
    
    return () => {
      ws.close()
    }
  }, [])
  
  const fetchReports = async () => {
    setLoading(true)
    try {
      const response = await fetch('http://localhost:8000/api/reports')
      const data = await response.json()
      setReports(data.reports || [])
      
      // Auto-select latest report if available
      if (data.reports && data.reports.length > 0) {
        setSelectedReport(data.reports[data.reports.length - 1])
      }
    } catch (error) {
      console.error('Failed to fetch reports:', error)
    } finally {
      setLoading(false)
    }
  }
  
  const showNotification = (message: string, severity: string) => {
    // Create a notification element
    const notification = document.createElement('div')
    notification.className = `fixed top-4 right-4 p-4 rounded-lg text-white font-semibold animate-pulse z-50 ${
      severity === 'high' ? 'bg-red-600' : 'bg-yellow-600'
    }`
    notification.innerHTML = `
      <div class="flex items-center">
        <span class="text-2xl mr-2">🚨</span>
        <div>
          <div class="font-bold">${message}</div>
          <div class="text-sm">Attack auto-stopped by AI Agent</div>
        </div>
      </div>
    `
    document.body.appendChild(notification)
    
    // Remove after 5 seconds
    setTimeout(() => {
      notification.remove()
    }, 5000)
  }
  
  const formatDuration = (seconds: number) => {
    if (seconds < 60) return `${seconds.toFixed(1)}s`
    return `${(seconds / 60).toFixed(1)}m`
  }
  
  const formatBytes = (bytes: number) => {
    if (bytes < 1024) return `${bytes} B`
    if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(2)} KB`
    return `${(bytes / (1024 * 1024)).toFixed(2)} MB`
  }
  
  return (
    <div className="bg-gray-900 rounded-lg p-6">
      <div className="mb-6">
        <h2 className="text-2xl font-bold text-white mb-2">📊 Attack Reports</h2>
        <p className="text-gray-400">AI-generated reports from detected DDoS attacks</p>
        
        {autoDetected && (
          <div className="mt-4 p-4 bg-green-900/20 border border-green-600 rounded-lg">
            <p className="text-green-400">
              ✅ AI Agent automatically detected and stopped attack: {autoDetected}
            </p>
          </div>
        )}
      </div>
      
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Report List */}
        <div className="lg:col-span-1">
          <h3 className="text-lg font-semibold text-white mb-4">Recent Reports</h3>
          
          {loading ? (
            <div className="text-gray-400">Loading reports...</div>
          ) : reports.length === 0 ? (
            <div className="text-gray-400">No attack reports available</div>
          ) : (
            <div className="space-y-2">
              {reports.map((report) => (
                <button
                  key={report.id}
                  onClick={() => setSelectedReport(report)}
                  className={`w-full text-left p-3 rounded-lg transition-colors ${
                    selectedReport?.id === report.id
                      ? 'bg-blue-600 text-white'
                      : 'bg-gray-800 text-gray-300 hover:bg-gray-700'
                  }`}
                >
                  <div className="font-semibold">{report.attack_summary.type}</div>
                  <div className="text-sm opacity-75">
                    {new Date(report.created_at).toLocaleString()}
                  </div>
                  <div className="text-xs mt-1">
                    <span className={`inline-block px-2 py-1 rounded ${
                      report.attack_summary.severity === 'critical' ? 'bg-red-600' :
                      report.attack_summary.severity === 'high' ? 'bg-orange-600' :
                      report.attack_summary.severity === 'medium' ? 'bg-yellow-600' :
                      'bg-green-600'
                    }`}>
                      {report.attack_summary.severity.toUpperCase()}
                    </span>
                    {report.id === autoDetected && (
                      <span className="ml-2 text-green-400">AUTO-STOPPED</span>
                    )}
                  </div>
                </button>
              ))}
            </div>
          )}
        </div>
        
        {/* Report Details */}
        <div className="lg:col-span-2">
          {selectedReport ? (
            <div className="space-y-6">
              <div className="bg-gray-800 rounded-lg p-6">
                <h3 className="text-xl font-bold text-white mb-4">
                  {selectedReport.attack_summary.type} Attack
                </h3>
                
                <div className="grid grid-cols-2 gap-4 mb-4">
                  <div>
                    <div className="text-gray-400 text-sm">Duration</div>
                    <div className="text-white font-semibold">
                      {formatDuration(selectedReport.attack_summary.duration_seconds)}
                    </div>
                  </div>
                  <div>
                    <div className="text-gray-400 text-sm">Status</div>
                    <div className="text-white font-semibold capitalize">
                      {selectedReport.attack_summary.status}
                    </div>
                  </div>
                  <div>
                    <div className="text-gray-400 text-sm">Severity</div>
                    <div className={`font-semibold capitalize ${
                      selectedReport.attack_summary.severity === 'critical' ? 'text-red-400' :
                      selectedReport.attack_summary.severity === 'high' ? 'text-orange-400' :
                      selectedReport.attack_summary.severity === 'medium' ? 'text-yellow-400' :
                      'text-green-400'
                    }`}>
                      {selectedReport.attack_summary.severity}
                    </div>
                  </div>
                  <div>
                    <div className="text-gray-400 text-sm">Report ID</div>
                    <div className="text-white text-xs font-mono">
                      {selectedReport.id}
                    </div>
                  </div>
                </div>
              </div>
              
              {/* Traffic Statistics */}
              <div className="bg-gray-800 rounded-lg p-6">
                <h4 className="text-lg font-semibold text-white mb-4">Traffic Statistics</h4>
                
                <div className="grid grid-cols-3 gap-4">
                  <div>
                    <div className="text-gray-400 text-sm">Total Requests</div>
                    <div className="text-2xl font-bold text-white">
                      {selectedReport.traffic_statistics.total_requests.toLocaleString()}
                    </div>
                  </div>
                  <div>
                    <div className="text-gray-400 text-sm">Blocked</div>
                    <div className="text-2xl font-bold text-red-400">
                      {selectedReport.traffic_statistics.blocked_requests.toLocaleString()}
                    </div>
                  </div>
                  <div>
                    <div className="text-gray-400 text-sm">Data Sent</div>
                    <div className="text-2xl font-bold text-yellow-400">
                      {formatBytes(selectedReport.traffic_statistics.bytes_sent)}
                    </div>
                  </div>
                </div>
                
                <div className="mt-4 pt-4 border-t border-gray-700">
                  <div className="flex justify-between items-center">
                    <span className="text-gray-400">Mitigation Effectiveness</span>
                    <span className="text-2xl font-bold text-green-400">
                      {selectedReport.mitigation_actions.effectiveness_percentage.toFixed(1)}%
                    </span>
                  </div>
                  <div className="w-full bg-gray-700 rounded-full h-2 mt-2">
                    <div
                      className="bg-green-400 h-2 rounded-full"
                      style={{ width: `${selectedReport.mitigation_actions.effectiveness_percentage}%` }}
                    />
                  </div>
                </div>
              </div>
              
              {/* Mitigation Actions */}
              <div className="bg-gray-800 rounded-lg p-6">
                <h4 className="text-lg font-semibold text-white mb-4">Mitigation Actions</h4>
                
                <div className="space-y-2">
                  <div className="flex justify-between">
                    <span className="text-gray-400">IPs Blocked</span>
                    <span className="text-white font-semibold">
                      {selectedReport.mitigation_actions.ips_blocked.length}
                    </span>
                  </div>
                  <div className="flex justify-between">
                    <span className="text-gray-400">Response Time</span>
                    <span className="text-white font-semibold">
                      {selectedReport.mitigation_actions.response_time_seconds.toFixed(2)}s
                    </span>
                  </div>
                </div>
                
                {selectedReport.mitigation_actions.ips_blocked.length > 0 && (
                  <div className="mt-4">
                    <div className="text-sm text-gray-400 mb-2">Blocked IPs:</div>
                    <div className="flex flex-wrap gap-2">
                      {selectedReport.mitigation_actions.ips_blocked.slice(0, 10).map((ip, idx) => (
                        <span key={idx} className="px-2 py-1 bg-red-900/50 text-red-400 rounded text-xs font-mono">
                          {ip}
                        </span>
                      ))}
                      {selectedReport.mitigation_actions.ips_blocked.length > 10 && (
                        <span className="px-2 py-1 bg-gray-700 text-gray-400 rounded text-xs">
                          +{selectedReport.mitigation_actions.ips_blocked.length - 10} more
                        </span>
                      )}
                    </div>
                  </div>
                )}
              </div>
              
              {/* Recommendations */}
              {selectedReport.recommendations && selectedReport.recommendations.length > 0 && (
                <div className="bg-gray-800 rounded-lg p-6">
                  <h4 className="text-lg font-semibold text-white mb-4">AI Recommendations</h4>
                  
                  <ul className="space-y-2">
                    {selectedReport.recommendations.map((rec, idx) => (
                      <li key={idx} className="flex items-start">
                        <span className="text-blue-400 mr-2">•</span>
                        <span className="text-gray-300">{rec}</span>
                      </li>
                    ))}
                  </ul>
                </div>
              )}
              
              {/* Visualizations */}
              {selectedReport.visualizations && (
                <div className="space-y-6">
                  {selectedReport.visualizations.attack_flow && (
                    <div className="bg-gray-800 rounded-lg p-6">
                      <h4 className="text-lg font-semibold text-white mb-4">Attack Flow Visualization</h4>
                      <MermaidDiagram 
                        chart={selectedReport.visualizations.attack_flow} 
                        id={`attack-flow-${selectedReport.id}`}
                      />
                    </div>
                  )}
                  
                  {selectedReport.visualizations.mitigation_flow && (
                    <div className="bg-gray-800 rounded-lg p-6">
                      <h4 className="text-lg font-semibold text-white mb-4">Mitigation Flow</h4>
                      <MermaidDiagram 
                        chart={selectedReport.visualizations.mitigation_flow} 
                        id={`mitigation-flow-${selectedReport.id}`}
                      />
                    </div>
                  )}
                  
                  {selectedReport.visualizations.statistics && (
                    <div className="bg-gray-800 rounded-lg p-6">
                      <h4 className="text-lg font-semibold text-white mb-4">Traffic Statistics</h4>
                      <MermaidDiagram 
                        chart={selectedReport.visualizations.statistics} 
                        id={`statistics-${selectedReport.id}`}
                      />
                    </div>
                  )}
                </div>
              )}
            </div>
          ) : (
            <div className="bg-gray-800 rounded-lg p-6 text-center text-gray-400">
              Select a report to view details
            </div>
          )}
        </div>
      </div>
    </div>
  )
}