interface MetricsGridProps {
  metrics: {
    totalPackets: number;
    threatCount: number;
    activeSessions: number;
    bandwidth: number;
    responseTime: number;
    criticalAlerts: number;
  };
}

export default function MetricsGrid({ metrics }: MetricsGridProps) {
  const metricCards = [
    {
      label: 'Total Packets',
      value: metrics.totalPackets.toLocaleString(),
      change: '↑ 12% from last hour',
      changeType: 'positive'
    },
    {
      label: 'Threats Detected',
      value: metrics.threatCount.toLocaleString(),
      change: metrics.threatCount > 0 ? `↑ ${metrics.threatCount} new threats` : 'No threats',
      changeType: metrics.threatCount > 0 ? 'negative' : 'positive'
    },
    {
      label: 'Active Sessions',
      value: metrics.activeSessions.toLocaleString(),
      change: '↑ 5 new connections',
      changeType: 'positive'
    },
    {
      label: 'Bandwidth',
      value: `${metrics.bandwidth.toFixed(1)} MB/s`,
      change: 'Normal traffic',
      changeType: 'positive'
    },
    {
      label: 'Avg Response Time',
      value: `${metrics.responseTime}ms`,
      change: '↓ 15ms improvement',
      changeType: 'positive'
    },
    {
      label: 'Critical Alerts',
      value: metrics.criticalAlerts.toLocaleString(),
      change: metrics.criticalAlerts > 0 ? 'Requires attention' : 'All clear',
      changeType: metrics.criticalAlerts > 0 ? 'negative' : 'positive'
    }
  ];

  return (
    <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 xl:grid-cols-6 gap-4 mb-6">
      {metricCards.map((metric, index) => (
        <div
          key={index}
          className="bg-zinc-900 rounded p-4 border border-zinc-800 relative overflow-hidden group hover:border-white transition-all"
        >
          <div className="absolute top-0 left-0 w-full h-0.5 bg-white" />
          
          <div className="text-zinc-500 text-xs font-semibold uppercase tracking-wider mb-2">
            {metric.label}
          </div>
          
          <div className="text-2xl font-bold text-white mb-2">
            {metric.value}
          </div>
          
          <div className={`text-xs ${
            metric.changeType === 'positive' ? 'text-zinc-400' : 'text-white'
          }`}>
            {metric.change}
          </div>
        </div>
      ))}
    </div>
  );
}