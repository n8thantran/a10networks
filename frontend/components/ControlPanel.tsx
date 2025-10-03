"use client";

import { useState } from 'react';

interface ControlPanelProps {
  onStartCapture: () => void;
  onStopCapture: () => void;
  onSearch: (query: string) => void;
  isCapturing: boolean;
}

export default function ControlPanel({ onStartCapture, onStopCapture, onSearch, isCapturing }: ControlPanelProps) {
  const [searchQuery, setSearchQuery] = useState('');

  return (
    <div className="grid grid-cols-1 md:grid-cols-3 gap-4 mb-6">
      <div className="bg-zinc-900 rounded p-4 border border-zinc-800">
        <label className="block text-sm font-medium text-zinc-400 mb-2">
          Monitor Control
        </label>
        <div className="text-xs text-zinc-500 mb-3">
          Monitoring port 8080 for HTTP traffic
        </div>
        <button
          onClick={() => {
            console.log('Start Capture clicked');
            onStartCapture();
          }}
          disabled={isCapturing}
          className="w-full px-4 py-2 bg-white text-black font-medium rounded hover:bg-zinc-200 transition-all disabled:opacity-50 disabled:cursor-not-allowed"
          type="button"
        >
          {isCapturing ? 'Capturing...' : 'Start Capture'}
        </button>
      </div>

      <div className="bg-zinc-900 rounded p-4 border border-zinc-800">
        <label className="block text-sm font-medium text-zinc-400 mb-2">
          Connection Status
        </label>
        <div className="text-xs text-zinc-500 mb-3">
          {isCapturing ? 'Connected to WebSocket' : 'Disconnected'}
        </div>
        <button
          onClick={onStopCapture}
          disabled={!isCapturing}
          className="w-full px-4 py-2 bg-zinc-800 text-white font-medium rounded border border-zinc-700 hover:bg-zinc-700 transition-all disabled:opacity-50 disabled:cursor-not-allowed"
        >
          Stop Capture
        </button>
      </div>

      <div className="bg-zinc-900 rounded p-4 border border-zinc-800">
        <label className="block text-sm font-medium text-zinc-400 mb-2">
          Test Tools
        </label>
        <input
          type="text"
          value={searchQuery}
          onChange={(e) => setSearchQuery(e.target.value)}
          onKeyPress={(e) => e.key === 'Enter' && onSearch(searchQuery)}
          className="w-full px-3 py-2 bg-black border border-zinc-700 rounded text-white placeholder-zinc-600 focus:outline-none focus:border-white mb-3"
          placeholder="e.g., ' OR '1'='1 or <script>alert(1)</script>"
        />
        <button
          onClick={() => onSearch(searchQuery)}
          className="w-full px-4 py-2 bg-zinc-800 text-white font-medium rounded border border-zinc-700 hover:bg-zinc-700 transition-all mb-2"
        >
          Send Attack
        </button>
        <button
          onClick={() => window.open('http://localhost:8001', '_blank')}
          className="w-full px-4 py-2 bg-white text-black font-medium rounded hover:bg-zinc-200 transition-all"
        >
          Open Test Site 🛒
        </button>
      </div>
    </div>
  );
}