interface ThreatMonitorProps {
  threatData: {
    xss: number;
    sql: number;
    dos: number;
    csrf: number;
    scan: number;
  };
  packets: Array<{
    threats?: Array<{
      type: string;
      pattern: string;
      severity: string;
    }>;
    threat_level: string;
  }>;
}

export default function ThreatMonitor({ threatData, packets }: ThreatMonitorProps) {
  const recentThreats = packets
    .filter(p => p.threats && p.threats.length > 0)
    .slice(0, 5)
    .map(p => p.threats![0]);

  const bars = [
    { label: 'XSS', value: threatData.xss },
    { label: 'SQL', value: threatData.sql },
    { label: 'DoS', value: threatData.dos },
    { label: 'CSRF', value: threatData.csrf },
    { label: 'Scan', value: threatData.scan }
  ];

  return (
    <div className="bg-zinc-900 rounded border border-zinc-800 p-6">
      <h2 className="text-xl font-semibold text-white mb-4">Threat Analysis</h2>
      
      <div className="mb-6">
        <div className="h-40 flex items-end justify-between gap-2">
          {bars.map((bar, index) => (
            <div key={index} className="flex-1 flex flex-col items-center justify-end">
              <div 
                className="w-full bg-white rounded-t transition-all duration-500"
                style={{ height: `${bar.value}%` }}
              />
              <span className="text-xs text-zinc-500 mt-2">{bar.label}</span>
            </div>
          ))}
        </div>
      </div>
      
      <div className="space-y-2">
        <h3 className="text-sm font-semibold text-zinc-500 mb-2">Recent Threats</h3>
        {recentThreats.length === 0 ? (
          <div className="text-center py-4 text-zinc-600 text-sm">
            No threats detected yet
          </div>
        ) : (
          recentThreats.map((threat, index) => (
            <div
              key={index}
              className="bg-black rounded p-3 border-l-2 border-white"
            >
              <div className="text-sm font-semibold text-white">
                {threat.type}
              </div>
              <div className="text-xs text-zinc-500 mt-1">
                {threat.pattern}
              </div>
            </div>
          ))
        )}
      </div>
    </div>
  );
}