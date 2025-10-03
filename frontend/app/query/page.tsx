import NetworkQuery from '@/components/NetworkQuery'
import AttackReportViewer from '@/components/AttackReportViewer'

export default function QueryPage() {
  return (
    <div className="min-h-screen bg-black">
      <header className="bg-gray-900 border-b border-gray-800">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
          <div className="flex items-center justify-between h-16">
            <div className="flex items-center">
              <div className="flex-shrink-0">
                <div className="w-8 h-8 bg-blue-600 rounded flex items-center justify-center">
                  <span className="text-white font-bold">NS</span>
                </div>
              </div>
              <div className="ml-4">
                <h1 className="text-xl font-semibold text-white">Network Query & Attack Reports</h1>
              </div>
            </div>
            <nav className="flex space-x-4">
              <a href="/" className="text-gray-400 hover:text-white px-3 py-2 rounded-md text-sm font-medium">
                Home
              </a>
              <a href="/dashboard" className="text-gray-400 hover:text-white px-3 py-2 rounded-md text-sm font-medium">
                Dashboard
              </a>
              <a href="/query" className="text-white px-3 py-2 rounded-md text-sm font-medium bg-gray-800">
                Query
              </a>
              <a href="/attack" className="text-gray-400 hover:text-white px-3 py-2 rounded-md text-sm font-medium">
                Attack Panel
              </a>
            </nav>
          </div>
        </div>
      </header>

      <main className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-8 space-y-8">
        <NetworkQuery />
        <AttackReportViewer />
      </main>
    </div>
  )
}