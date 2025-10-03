'use client'

import React, { useState } from 'react'
import MermaidDiagram from './MermaidDiagram'

interface QueryResult {
  success: boolean
  query: string
  type?: string
  data?: any
  visualization?: string
  mermaidDiagram?: string
  error?: string
}

interface NetworkNode {
  ip: string
  hostname?: string
  type?: string
  os?: string
  ports?: number[]
  services?: string[]
  risk_score?: number
  packet_count?: number
}

interface NetworkConnection {
  source: string
  target: string
  protocol?: string
  port?: number
  service?: string
  threat_level?: string
  packet_count?: number
}

export default function NetworkQuery() {
  const [query, setQuery] = useState('')
  const [result, setResult] = useState<QueryResult | null>(null)
  const [loading, setLoading] = useState(false)
  const [history, setHistory] = useState<string[]>([])

  const generateTopologyDiagram = (nodes: NetworkNode[], connections: NetworkConnection[]) => {
    // Check if we have data to visualize
    if (!nodes || nodes.length === 0) {
      console.log('No nodes to visualize')
      return 'graph TB\n    empty[No Network Data Available]'
    }
    
    console.log('Generating topology with', nodes.length, 'nodes and', connections.length, 'connections')
    
    // Group nodes by type for better visualization
    const routers = nodes.filter(n => n.type === 'router')
    const firewalls = nodes.filter(n => n.type === 'firewall')
    const servers = nodes.filter(n => n.type === 'server')
    const hosts = nodes.filter(n => n.type === 'host')
    
    // Group hosts by subnet for cleaner visualization
    const subnetGroups: { [key: string]: NetworkNode[] } = {}
    hosts.forEach(host => {
      const subnet = host.ip.split('.').slice(0, 3).join('.')
      if (!subnetGroups[subnet]) {
        subnetGroups[subnet] = []
      }
      subnetGroups[subnet].push(host)
    })

    let diagram = 'graph TB\n'
    
    // Add core infrastructure nodes first
    if (routers.length > 0) {
      diagram += '    subgraph core["Core Infrastructure"]\n'
      diagram += '        subgraph routers["Routers"]\n'
      routers.forEach(node => {
        const id = node.ip.replace(/\./g, '_')
        const label = node.hostname || node.ip
        diagram += `            ${id}["🔄 ${label}"]\n`
      })
      diagram += '        end\n'
      
      if (firewalls.length > 0) {
        diagram += '        subgraph firewalls["Firewalls"]\n'
        firewalls.forEach(node => {
          const id = node.ip.replace(/\./g, '_')
          const label = node.hostname || node.ip
          const portInfo = node.ports?.length ? ` (${node.ports.length} ports)` : ''
          diagram += `            ${id}["🛡️ ${label}${portInfo}"]\n`
        })
        diagram += '        end\n'
      }
      diagram += '    end\n\n'
    }

    // Add servers
    if (servers.length > 0) {
      diagram += '    subgraph services["Services & Servers"]\n'
      servers.forEach(node => {
        const id = node.ip.replace(/\./g, '_')
        const label = node.hostname || node.ip
        const portList = node.ports?.length ? ` [${node.ports.slice(0, 3).join(', ')}${node.ports.length > 3 ? '...' : ''}]` : ''
        diagram += `        ${id}["💾 ${label}${portList}"]\n`
      })
      diagram += '    end\n\n'
    }

    // Add host subnets - aggregate large groups
    Object.entries(subnetGroups).forEach(([subnet, subnetHosts]) => {
      if (subnetHosts.length > 20) {
        // Create aggregate node for large subnets
        const subnetId = `subnet_${subnet.replace(/\./g, '_')}`
        diagram += `    ${subnetId}["📦 ${subnet}.0/24<br/>${subnetHosts.length} hosts"]\n`
        
        // Show only the most active hosts (by packet count)
        const topHosts = subnetHosts
          .filter(h => h.packet_count && h.packet_count > 10)
          .sort((a, b) => (b.packet_count || 0) - (a.packet_count || 0))
          .slice(0, 5)
        
        if (topHosts.length > 0) {
          diagram += `    subgraph ${subnetId}_active["Active Hosts in ${subnet}.x"]\n`
          topHosts.forEach(node => {
            const id = node.ip.replace(/\./g, '_')
            const label = node.hostname || node.ip.split('.')[3]
            const os = node.os ? ` (${node.os})` : ''
            diagram += `        ${id}["🖥️ ${label}${os}"]\n`
          })
          diagram += '    end\n'
          
          // Connect active hosts to subnet aggregate
          topHosts.forEach(node => {
            const id = node.ip.replace(/\./g, '_')
            diagram += `    ${id} -.-> ${subnetId}\n`
          })
        }
      } else if (subnetHosts.length > 0 && subnetHosts.length <= 20) {
        // Show all hosts for small subnets
        diagram += `    subgraph ${subnet.replace(/\./g, '_')}_subnet["${subnet}.0/24 Network"]\n`
        subnetHosts.forEach(node => {
          const id = node.ip.replace(/\./g, '_')
          const label = node.hostname || `${subnet}.${node.ip.split('.')[3]}`
          const os = node.os ? ` - ${node.os}` : ''
          diagram += `        ${id}["🖥️ ${label}${os}"]\n`
        })
        diagram += '    end\n'
      }
    })

    // Add important connections - focus on high traffic and threats
    if (connections && connections.length > 0) {
      diagram += '\n    %% High Traffic Connections\n'
      
      // Filter and sort connections
      const importantConnections = connections
        .filter(conn => {
          // Include high packet count or threat connections
          return (conn.packet_count && conn.packet_count > 10) || 
                 (conn.threat_level && conn.threat_level !== 'none')
        })
        .sort((a, b) => (b.packet_count || 0) - (a.packet_count || 0))
        .slice(0, 30) // Show top 30 connections
      
      importantConnections.forEach(conn => {
        const sourceId = conn.source.replace(/\./g, '_')
        const targetId = conn.target.replace(/\./g, '_')
        const label = conn.service || conn.protocol || ''
        
        // Check if both nodes exist
        const sourceExists = nodes.find(n => n.ip === conn.source)
        const targetExists = nodes.find(n => n.ip === conn.target)
        
        if (sourceExists && targetExists) {
          // Only show connections for visible nodes
          const sourceSubnet = conn.source.split('.').slice(0, 3).join('.')
          const targetSubnet = conn.target.split('.').slice(0, 3).join('.')
          
          // Skip if both are in large subnets (unless they're important nodes)
          if (subnetGroups[sourceSubnet]?.length > 20 && subnetGroups[targetSubnet]?.length > 20) {
            if (sourceExists.type === 'host' && targetExists.type === 'host') {
              return // Skip host-to-host in large subnets
            }
          }
          
          if (conn.threat_level === 'critical') {
            diagram += `    ${sourceId} ===>|⚠️ ${label}| ${targetId}\n`
          } else if (conn.threat_level === 'high') {
            diagram += `    ${sourceId} -.->|⚠️ ${label}| ${targetId}\n`
          } else if (conn.packet_count && conn.packet_count > 50) {
            diagram += `    ${sourceId} ==>|${label}| ${targetId}\n`
          } else {
            diagram += `    ${sourceId} -->|${label}| ${targetId}\n`
          }
        }
      })
    }

    // Add styling
    diagram += '\n    %% Styling\n'
    diagram += '    classDef router fill:#3b82f6,stroke:#1e40af,stroke-width:3px,color:#fff\n'
    diagram += '    classDef firewall fill:#ef4444,stroke:#dc2626,stroke-width:3px,color:#fff\n'
    diagram += '    classDef server fill:#10b981,stroke:#059669,stroke-width:2px,color:#fff\n'
    diagram += '    classDef host fill:#6b7280,stroke:#374151,stroke-width:1px,color:#fff\n'
    diagram += '    classDef subnet fill:#312e81,stroke:#4c1d95,stroke-width:2px,color:#fff\n'
    diagram += '    classDef active fill:#fbbf24,stroke:#f59e0b,stroke-width:2px,color:#000\n'
    
    // Apply styles
    routers.forEach(node => {
      const id = node.ip.replace(/\./g, '_')
      diagram += `    class ${id} router\n`
    })
    
    firewalls.forEach(node => {
      const id = node.ip.replace(/\./g, '_')
      diagram += `    class ${id} firewall\n`
    })
    
    servers.forEach(node => {
      const id = node.ip.replace(/\./g, '_')
      diagram += `    class ${id} server\n`
    })
    
    // Style subnet aggregates
    Object.entries(subnetGroups).forEach(([subnet]) => {
      if (subnetGroups[subnet].length > 20) {
        const subnetId = `subnet_${subnet.replace(/\./g, '_')}`
        diagram += `    class ${subnetId} subnet\n`
      }
    })

    return diagram
  }

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault()
    if (!query.trim()) return

    setLoading(true)
    
    try {
      const response = await fetch('http://localhost:8000/api/query', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({ query })
      })

      const data = await response.json()
      
      // Debug logging
      console.log('Query response:', data)
      console.log('Has nodes?', data.data?.nodes)
      console.log('Has connections?', data.data?.connections)
      console.log('Visualization type:', data.visualization)
      
      // Generate network topology diagram if we have nodes and connections
      if (data.data?.nodes && data.data?.connections) {
        console.log('Generating topology diagram with:', {
          nodeCount: data.data.nodes.length,
          connectionCount: data.data.connections.length
        })
        
        const diagram = generateTopologyDiagram(data.data.nodes, data.data.connections)
        console.log('Generated diagram:', diagram)
        data.mermaidDiagram = diagram
      }
      
      setResult(data)
      
      // Add to history
      setHistory(prev => [query, ...prev.slice(0, 9)])
    } catch (error) {
      setResult({
        success: false,
        query,
        error: 'Failed to execute query'
      })
    } finally {
      setLoading(false)
    }
  }

  const exampleQueries = [
    "What is the network topology",
    "Show all nodes",
    "Show top talkers",
    "Show recent anomalies",
    "What protocols are being used",
    "Show connections from 192.168.1.1",
    "Who is talking to 192.168.1.100",
    "Show TCP connections",
    "What services are running",
    "Show threats",
    "Show attack reports",
    "What attacks happened today",
    "Show the latest attack",
    "Get attack statistics",
    "How many attacks were there"
  ]

  return (
    <div className="bg-gray-900 rounded-lg p-6">
      <div className="mb-6">
        <h2 className="text-2xl font-bold text-white mb-4">Network Query Interface</h2>
        
        <form onSubmit={handleSubmit} className="flex gap-2">
          <input
            type="text"
            value={query}
            onChange={(e) => setQuery(e.target.value)}
            placeholder="Ask about your network... (e.g., 'Show all connections' or 'Find threats')"
            className="flex-1 px-4 py-2 bg-gray-800 text-white rounded-lg focus:outline-none focus:ring-2 focus:ring-blue-500"
            disabled={loading}
          />
          <button
            type="submit"
            disabled={loading}
            className="px-6 py-2 bg-blue-600 text-white rounded-lg hover:bg-blue-700 disabled:opacity-50 disabled:cursor-not-allowed"
          >
            {loading ? 'Processing...' : 'Query'}
          </button>
        </form>

        <div className="mt-3 flex flex-wrap gap-2">
          <span className="text-gray-400 text-sm">Try:</span>
          {exampleQueries.map((example, idx) => (
            <button
              key={idx}
              onClick={() => setQuery(example)}
              className="text-xs px-2 py-1 bg-gray-800 text-gray-300 rounded hover:bg-gray-700"
            >
              {example}
            </button>
          ))}
        </div>
      </div>

      {result && (
        <div className="space-y-4">
          {result.success ? (
            <>
              <div className="bg-gray-800 rounded-lg p-4">
                <div className="flex items-start justify-between mb-2">
                  <div>
                    <h3 className="text-lg font-semibold text-white">Query Result</h3>
                    <p className="text-gray-400 text-sm">Type: {result.type}</p>
                  </div>
                  <span className="text-green-400 text-sm">Success</span>
                </div>
                
                {result.data?.message && (
                  <p className="text-gray-300 mb-3">{result.data.message}</p>
                )}

                {result.visualization && (
                  <div className="text-sm text-gray-400">
                    Visualization: <span className="text-blue-400">{result.visualization}</span>
                  </div>
                )}
              </div>

              {result.mermaidDiagram && (
                <div className="bg-gray-800 rounded-lg p-4">
                  <h3 className="text-lg font-semibold text-white mb-4">Network Diagram</h3>
                  <MermaidDiagram 
                    chart={result.mermaidDiagram} 
                    id={`network-topology-${Date.now()}`}
                  />
                </div>
              )}

              {result.data && (
                <div className="bg-gray-800 rounded-lg p-4">
                  <h3 className="text-lg font-semibold text-white mb-2">Data</h3>
                  <pre className="text-gray-300 text-sm overflow-auto max-h-64 bg-gray-900 p-3 rounded">
                    {JSON.stringify(result.data, null, 2)}
                  </pre>
                </div>
              )}
            </>
          ) : (
            <div className="bg-red-900/20 border border-red-600 rounded-lg p-4">
              <h3 className="text-lg font-semibold text-red-400">Query Failed</h3>
              <p className="text-gray-300 mt-1">{result.error}</p>
            </div>
          )}
        </div>
      )}

      {history.length > 0 && (
        <div className="mt-6 pt-6 border-t border-gray-800">
          <h3 className="text-sm font-semibold text-gray-400 mb-2">Recent Queries</h3>
          <div className="space-y-1">
            {history.map((item, idx) => (
              <button
                key={idx}
                onClick={() => setQuery(item)}
                className="block w-full text-left text-sm text-gray-500 hover:text-gray-300 truncate"
              >
                {item}
              </button>
            ))}
          </div>
        </div>
      )}
    </div>
  )
}