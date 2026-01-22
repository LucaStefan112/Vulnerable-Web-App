'use client'

import { useState } from 'react'
import { useRouter } from 'next/navigation'
import Link from 'next/link'

export default function UploadPage() {
  const router = useRouter()
  const [file, setFile] = useState<File | null>(null)
  const [uploading, setUploading] = useState(false)
  const [error, setError] = useState('')
  const [success, setSuccess] = useState('')
  const [uploadUrl, setUploadUrl] = useState('')

  const handleFileChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    if (e.target.files && e.target.files[0]) {
      setFile(e.target.files[0])
      setError('')
      setSuccess('')
    }
  }

  const handleUpload = async (e: React.FormEvent) => {
    e.preventDefault()
    setError('')
    setSuccess('')
    setUploadUrl('')

    if (!file) {
      setError('Please select a file')
      return
    }

    setUploading(true)

    try {
      const formData = new FormData()
      formData.append('file', file)

      // INTENTIONALLY VULNERABLE: No file validation on client or server
      const response = await fetch('/api/upload', {
        method: 'POST',
        body: formData,
      })

      if (!response.ok) {
        const data = await response.json()
        throw new Error(data.error || 'Upload failed')
      }

      const data = await response.json()
      setSuccess('File uploaded successfully!')
      setUploadUrl(data.url)
      setFile(null)
      
      // Reset file input
      const fileInput = document.getElementById('file-input') as HTMLInputElement
      if (fileInput) {
        fileInput.value = ''
      }
    } catch (err: any) {
      setError(err.message || 'Upload failed')
    } finally {
      setUploading(false)
    }
  }

  return (
    <div className="min-h-screen bg-zinc-50 dark:bg-black">
      <nav className="border-b border-zinc-200 bg-white dark:border-zinc-800 dark:bg-zinc-900">
        <div className="mx-auto max-w-7xl px-4 sm:px-6 lg:px-8">
          <div className="flex h-16 items-center justify-between">
            <div className="flex items-center gap-4">
              <Link
                href="/notes"
                className="text-zinc-600 hover:text-zinc-900 dark:text-zinc-400 dark:hover:text-zinc-50"
              >
                ← Back to Notes
              </Link>
              <h1 className="text-xl font-bold text-zinc-900 dark:text-zinc-50">
                File Upload
              </h1>
            </div>
          </div>
        </div>
      </nav>

      <main className="mx-auto max-w-2xl px-4 py-8 sm:px-6 lg:px-8">
        <div className="mb-6">
          <h2 className="text-2xl font-bold text-zinc-900 dark:text-zinc-50">
            Upload a File
          </h2>
          <p className="mt-2 text-sm text-zinc-600 dark:text-zinc-400">
            ⚠️ Intentionally Vulnerable: No file type validation, no size limits, files stored in public directory.
          </p>
        </div>

        <div className="rounded-lg border border-zinc-200 bg-white p-6 shadow-sm dark:border-zinc-800 dark:bg-zinc-900">
          <form onSubmit={handleUpload} className="space-y-4">
            {error && (
              <div className="rounded-md bg-red-50 p-4 text-red-800 dark:bg-red-900/20 dark:text-red-200">
                {error}
              </div>
            )}

            {success && (
              <div className="rounded-md bg-green-50 p-4 text-green-800 dark:bg-green-900/20 dark:text-green-200">
                {success}
                {uploadUrl && (
                  <div className="mt-2">
                    <p className="text-sm">File URL:</p>
                    <a
                      href={uploadUrl}
                      target="_blank"
                      rel="noopener noreferrer"
                      className="text-sm text-green-600 underline hover:text-green-700 dark:text-green-400"
                    >
                      {uploadUrl}
                    </a>
                  </div>
                )}
              </div>
            )}

            <div>
              <label
                htmlFor="file-input"
                className="block text-sm font-medium text-zinc-700 dark:text-zinc-300"
              >
                Select File
              </label>
              <input
                id="file-input"
                type="file"
                onChange={handleFileChange}
                className="mt-1 block w-full text-sm text-zinc-500 file:mr-4 file:rounded-md file:border-0 file:bg-zinc-100 file:px-4 file:py-2 file:text-sm file:font-semibold file:text-zinc-700 hover:file:bg-zinc-200 dark:file:bg-zinc-800 dark:file:text-zinc-200 dark:hover:file:bg-zinc-700"
              />
              {file && (
                <p className="mt-2 text-sm text-zinc-600 dark:text-zinc-400">
                  Selected: {file.name} ({(file.size / 1024).toFixed(2)} KB)
                </p>
              )}
            </div>

            <button
              type="submit"
              disabled={!file || uploading}
              className="w-full rounded-md bg-zinc-900 px-4 py-2 text-white hover:bg-zinc-800 focus:outline-none focus:ring-2 focus:ring-zinc-500 focus:ring-offset-2 disabled:opacity-50 dark:bg-zinc-50 dark:text-zinc-900 dark:hover:bg-zinc-200"
            >
              {uploading ? 'Uploading...' : 'Upload File'}
            </button>
          </form>
        </div>

        <div className="mt-6 rounded-lg border border-yellow-200 bg-yellow-50 p-4 dark:border-yellow-800 dark:bg-yellow-900/20">
          <h3 className="text-sm font-semibold text-yellow-800 dark:text-yellow-200">
            Security Vulnerabilities:
          </h3>
          <ul className="mt-2 list-disc list-inside space-y-1 text-sm text-yellow-700 dark:text-yellow-300">
            <li>No MIME type validation</li>
            <li>No file extension validation</li>
            <li>No file size limits</li>
            <li>Files stored in publicly accessible directory</li>
            <li>No virus scanning</li>
            <li>Path traversal possible via filename</li>
          </ul>
        </div>
      </main>
    </div>
  )
}
