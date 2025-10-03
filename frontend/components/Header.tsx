interface HeaderProps {
  isCapturing: boolean;
}

export default function Header({ isCapturing }: HeaderProps) {
  return (
    <header className="bg-black border-b border-zinc-800">
      <div className="container mx-auto px-4 py-4">
        <div className="flex justify-between items-center">
          <div className="flex items-center gap-3">
            <div className="w-10 h-10 bg-white rounded flex items-center justify-center">
              <svg className="w-6 h-6 text-black" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z" />
              </svg>
            </div>
            <h1 className="text-2xl font-bold text-white">
              NetSentinel Security Dashboard
            </h1>
          </div>
          
          <div className={`flex items-center gap-2 px-4 py-2 rounded-full border ${
            isCapturing 
              ? 'border-white text-white' 
              : 'border-zinc-600 text-zinc-400'
          }`}>
            <div className={`w-2 h-2 rounded-full ${
              isCapturing ? 'bg-white' : 'bg-zinc-600'
            } animate-pulse`} />
            <span className="text-sm font-medium">
              {isCapturing ? 'Capturing' : 'System Idle'}
            </span>
          </div>
        </div>
      </div>
    </header>
  );
}