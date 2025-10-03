import Link from 'next/link';

export default function Home() {
  return (
    <div className="min-h-screen bg-black flex items-center justify-center">
      <div className="text-center">
        <div className="mb-8">
          <div className="w-20 h-20 bg-white rounded flex items-center justify-center mx-auto mb-6">
            <svg className="w-12 h-12 text-black" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z" />
            </svg>
          </div>
          <h1 className="text-5xl font-bold text-white mb-4">
            NetSentinel
          </h1>
          <p className="text-xl text-zinc-500">
            Real-time Network Security Monitoring & Threat Detection
          </p>
        </div>
        
        <div className="space-y-4">
          <Link
            href="/dashboard"
            className="inline-block px-8 py-4 bg-white text-black font-semibold rounded hover:bg-zinc-200 transition-all transform hover:scale-105"
          >
            Open Dashboard
          </Link>
          
          <Link
            href="/attack"
            className="inline-block px-8 py-4 bg-red-600 text-white font-semibold rounded hover:bg-red-700 transition-all transform hover:scale-105 ml-4"
          >
            Attack Panel 🔥
          </Link>
          
          <div className="text-sm text-zinc-600 mt-4">
            <p>Powered by AI-driven threat analysis</p>
          </div>
        </div>
      </div>
    </div>
  );
}