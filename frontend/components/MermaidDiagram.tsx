'use client'

import React, { useEffect, useRef, useState } from 'react'
import mermaid from 'mermaid'

interface MermaidDiagramProps {
  chart: string
  id?: string
}

export default function MermaidDiagram({ chart, id = 'mermaid-diagram' }: MermaidDiagramProps) {
  const containerRef = useRef<HTMLDivElement>(null)
  const [isInitialized, setIsInitialized] = useState(false)

  useEffect(() => {
    // Initialize mermaid only once on the client side
    if (typeof window !== 'undefined' && !isInitialized) {
      mermaid.initialize({
        startOnLoad: false,
        theme: 'dark',
        themeVariables: {
          primaryColor: '#1e40af',
          primaryTextColor: '#fff',
          primaryBorderColor: '#60a5fa',
          lineColor: '#60a5fa',
          secondaryColor: '#1f2937',
          tertiaryColor: '#374151',
          background: '#111827',
          mainBkg: '#1f2937',
          secondBkg: '#374151',
          tertiaryBkg: '#4b5563',
          secondaryBorderColor: '#9ca3af',
          tertiaryBorderColor: '#d1d5db',
          textColor: '#f3f4f6',
          labelTextColor: '#f3f4f6',
          nodeTextColor: '#f3f4f6',
          errorBkgColor: '#ef4444',
          errorTextColor: '#fff',
          warningBkgColor: '#f59e0b',
          warningTextColor: '#fff',
          infoTextColor: '#fff',
          successTextColor: '#fff',
          clusterBkg: '#1f2937',
          clusterBorder: '#60a5fa',
          defaultLinkColor: '#60a5fa',
          edgeLabelBackground: '#1f2937',
          actorBorder: '#60a5fa',
          actorBkg: '#1f2937',
          actorTextColor: '#f3f4f6',
          actorLineColor: '#9ca3af',
          signalColor: '#f3f4f6',
          signalTextColor: '#f3f4f6',
          labelBoxBorderColor: '#60a5fa',
          labelBoxBkgColor: '#1f2937',
          labelTextColor: '#f3f4f6',
          loopTextColor: '#f3f4f6',
          activationBorderColor: '#60a5fa',
          activationBkgColor: '#374151',
          sequenceNumberColor: '#fff',
        },
        flowchart: {
          htmlLabels: true,
          curve: 'linear',
          nodeSpacing: 50,
          rankSpacing: 50,
          padding: 15,
        },
      })
      setIsInitialized(true)
    }
  }, [isInitialized])

  useEffect(() => {
    if (!chart || !containerRef.current || !isInitialized) return

    const renderDiagram = async () => {
      try {
        // Clear previous content
        if (containerRef.current) {
          containerRef.current.innerHTML = ''
        }

        // Generate unique id for this diagram
        const graphId = `mermaid-${Math.random().toString(36).substr(2, 9)}`
        
        // Create a pre element for the mermaid syntax
        const element = document.createElement('pre')
        element.className = 'mermaid'
        element.textContent = chart
        
        if (containerRef.current) {
          containerRef.current.appendChild(element)
          
          // Render the diagram using renderAsync
          const { svg } = await mermaid.render(graphId, chart)
          
          // Replace pre element with rendered SVG
          if (containerRef.current) {
            containerRef.current.innerHTML = svg
          }
        }
      } catch (error: any) {
        console.error('Failed to render Mermaid diagram:', error)
        console.log('Chart content:', chart)
        if (containerRef.current) {
          containerRef.current.innerHTML = `
            <div class="text-red-400 p-4 bg-red-900/20 rounded">
              <p class="font-semibold">Failed to render diagram</p>
              <p class="text-sm mt-2">${error?.message || error}</p>
              <details class="mt-2">
                <summary class="cursor-pointer text-xs">Chart content</summary>
                <pre class="text-xs mt-1 text-gray-400">${chart}</pre>
              </details>
            </div>
          `
        }
      }
    }

    renderDiagram()
  }, [chart, id, isInitialized])

  return (
    <div className="mermaid-container">
      <div ref={containerRef} className="flex justify-center items-center min-h-[200px] p-4 overflow-x-auto" />
    </div>
  )
}