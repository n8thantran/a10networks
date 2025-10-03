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

interface PacketStreamProps {
  packets: Packet[];
}

export default function PacketStream({ packets }: PacketStreamProps) {
  const getThreatLevelStyles = (level: string) => {
    switch (level) {
      case 'critical':
        return 'bg-white text-black border-white animate-pulse';
      case 'high':
        return 'bg-zinc-800 text-white border-white';
      case 'medium':
        return 'bg-black text-white border-zinc-500';
      default:
        return 'bg-black text-zinc-500 border-zinc-700';
    }
  };

  const formatTime = (timestamp: string) => {
    return new Date(timestamp).toLocaleTimeString('en-US', {
      hour: '2-digit',
      minute: '2-digit',
      second: '2-digit'
    });
  };

  return (
    <div className="bg-zinc-900 rounded border border-zinc-800 p-6">
      <div className="flex items-center gap-2 mb-4">
        <svg className="w-5 h-5 text-white" fill="none" stroke="currentColor" viewBox="0 0 24 24">
          <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M13 10V3L4 14h7v7l9-11h-7z" />
        </svg>
        <h2 className="text-xl font-semibold text-white">Live Packet Stream</h2>
      </div>
      
      <div className="space-y-3 max-h-[500px] overflow-y-auto">
        {packets.length === 0 ? (
          <div className="text-center py-8 text-zinc-500">
            Waiting for packets...
          </div>
        ) : (
          packets.map((packet) => (
            <div
              key={packet.id}
              className="bg-black rounded p-4 border border-zinc-800 hover:border-zinc-600 transition-all group"
            >
              <div className="flex justify-between items-center mb-3">
                <span className="font-mono text-sm text-zinc-400">{packet.id}</span>
                <div className="flex items-center gap-2">
                  <span className={`px-2 py-1 rounded-full text-xs font-semibold uppercase border ${getThreatLevelStyles(packet.threat_level)}`}>
                    {packet.threat_level}
                  </span>
                  <span className="text-xs text-zinc-500">{formatTime(packet.timestamp)}</span>
                </div>
              </div>
              
              <div className="grid grid-cols-2 gap-3 text-sm">
                <div className="flex justify-between">
                  <span className="text-zinc-500">Source:</span>
                  <span className="font-mono text-white">{packet.src_ip}:{packet.src_port}</span>
                </div>
                <div className="flex justify-between">
                  <span className="text-zinc-500">Destination:</span>
                  <span className="font-mono text-white">{packet.dst_ip}:{packet.dst_port}</span>
                </div>
                <div className="flex justify-between">
                  <span className="text-zinc-500">Protocol:</span>
                  <span className="font-mono text-white">{packet.protocol}</span>
                </div>
                <div className="flex justify-between">
                  <span className="text-zinc-500">Size:</span>
                  <span className="font-mono text-white">{packet.size} bytes</span>
                </div>
              </div>
              
              {packet.threats && packet.threats.length > 0 && (
                <div className="mt-3 pt-3 border-t border-zinc-800">
                  <div className="text-xs text-white">
                    Threat: {packet.threats[0].type} - {packet.threats[0].pattern}
                  </div>
                </div>
              )}
            </div>
          ))
        )}
      </div>
    </div>
  );
}