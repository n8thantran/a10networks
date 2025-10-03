interface LogEntry {
  id: string;
  timestamp: Date;
  message: string;
  type: 'info' | 'warning' | 'error' | 'success';
}

interface ActivityLogProps {
  logs: LogEntry[];
}

export default function ActivityLog({ logs }: ActivityLogProps) {
  const getLogIcon = (type: string) => {
    const colors = {
      info: 'bg-zinc-600',
      warning: 'bg-zinc-400',
      error: 'bg-white',
      success: 'bg-zinc-500'
    };
    return colors[type as keyof typeof colors] || colors.info;
  };

  const formatTime = (date: Date) => {
    return date.toLocaleTimeString('en-US', {
      hour: '2-digit',
      minute: '2-digit',
      second: '2-digit'
    });
  };

  return (
    <div className="bg-zinc-900 rounded border border-zinc-800 p-6">
      <h2 className="text-xl font-semibold text-white mb-4">Activity Log</h2>
      
      <div className="space-y-2 max-h-[300px] overflow-y-auto">
        {logs.length === 0 ? (
          <div className="text-center py-4 text-zinc-500">
            No activity yet
          </div>
        ) : (
          logs.map((log) => (
            <div key={log.id} className="flex items-start gap-3 py-2 border-b border-zinc-800">
              <div className={`w-2 h-2 rounded-full ${getLogIcon(log.type)} mt-1.5`} />
              <span className="text-xs text-zinc-600 min-w-[60px]">
                {formatTime(log.timestamp)}
              </span>
              <span className="text-sm text-white flex-1">
                {log.message}
              </span>
            </div>
          ))
        )}
      </div>
    </div>
  );
}