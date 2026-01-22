'use client'

import { useState, useEffect } from 'react'
import { useRouter } from 'next/navigation'
import Link from 'next/link'

interface Note {
  id: number
  title: string
  content: string
  userId: number
  createdAt: string
  updatedAt: string
}

export default function NotesPage() {
  const router = useRouter()
  const [notes, setNotes] = useState<Note[]>([])
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState('')
  const [showCreateForm, setShowCreateForm] = useState(false)
  const [newTitle, setNewTitle] = useState('')
  const [newContent, setNewContent] = useState('')
  const [user, setUser] = useState<any>(null)

  useEffect(() => {
    loadNotes()
    loadUser()
  }, [])

  const loadUser = async () => {
    try {
      const token = localStorage.getItem('token')
      if (!token) {
        router.push('/login')
        return
      }

      // Decode JWT to get user info (intentionally insecure - should verify on server)
      const payload = JSON.parse(atob(token.split('.')[1]))
      setUser(payload)
    } catch (err) {
      console.error('Error loading user:', err)
    }
  }

  const loadNotes = async () => {
    try {
      const token = localStorage.getItem('token')
      if (!token) {
        router.push('/login')
        return
      }

      const response = await fetch('/api/notes', {
        headers: {
          'Authorization': `Bearer ${token}`,
        },
      })

      if (!response.ok) {
        if (response.status === 401) {
          router.push('/login')
          return
        }
        throw new Error('Failed to load notes')
      }

      const data = await response.json()
      setNotes(data)
      setLoading(false)
    } catch (err) {
      setError('Failed to load notes')
      setLoading(false)
    }
  }

  const handleCreateNote = async (e: React.FormEvent) => {
    e.preventDefault()
    setError('')

    try {
      const token = localStorage.getItem('token')
      if (!token) {
        router.push('/login')
        return
      }

      const response = await fetch('/api/notes', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Authorization': `Bearer ${token}`,
        },
        body: JSON.stringify({
          title: newTitle,
          content: newContent,
        }),
      })

      if (!response.ok) {
        throw new Error('Failed to create note')
      }

      const note = await response.json()
      setNotes([note, ...notes])
      setNewTitle('')
      setNewContent('')
      setShowCreateForm(false)
    } catch (err) {
      setError('Failed to create note')
    }
  }

  const handleDeleteNote = async (id: number) => {
    if (!confirm('Are you sure you want to delete this note?')) {
      return
    }

    try {
      const token = localStorage.getItem('token')
      if (!token) {
        router.push('/login')
        return
      }

      const response = await fetch(`/api/notes/${id}`, {
        method: 'DELETE',
        headers: {
          'Authorization': `Bearer ${token}`,
        },
      })

      if (!response.ok) {
        throw new Error('Failed to delete note')
      }

      setNotes(notes.filter(note => note.id !== id))
    } catch (err) {
      setError('Failed to delete note')
    }
  }

  const handleViewNote = (id: number) => {
    // INTENTIONALLY VULNERABLE: Can view any note by ID (IDOR)
    router.push(`/notes/${id}`)
  }

  if (loading) {
    return (
      <div className="flex min-h-screen items-center justify-center">
        <div className="text-lg">Loading...</div>
      </div>
    )
  }

  return (
    <div className="min-h-screen bg-zinc-50 dark:bg-black">
      <nav className="border-b border-zinc-200 bg-white dark:border-zinc-800 dark:bg-zinc-900">
        <div className="mx-auto max-w-7xl px-4 sm:px-6 lg:px-8">
          <div className="flex h-16 items-center justify-between">
            <div className="flex items-center">
              <h1 className="text-xl font-bold text-zinc-900 dark:text-zinc-50">
                SecureNotes
              </h1>
            </div>
            <div className="flex items-center gap-4">
              {user && (
                <span className="text-sm text-zinc-600 dark:text-zinc-400">
                  {user.email} ({user.role})
                </span>
              )}
              <Link
                href="/upload"
                className="rounded-md bg-blue-600 px-4 py-2 text-sm text-white hover:bg-blue-700"
              >
                Upload
              </Link>
              {user?.role === 'admin' && (
                <Link
                  href="/admin"
                  className="rounded-md bg-zinc-900 px-4 py-2 text-sm text-white hover:bg-zinc-800 dark:bg-zinc-50 dark:text-zinc-900 dark:hover:bg-zinc-200"
                >
                  Admin
                </Link>
              )}
              <button
                onClick={() => {
                  localStorage.removeItem('token')
                  router.push('/login')
                }}
                className="rounded-md bg-red-600 px-4 py-2 text-sm text-white hover:bg-red-700"
              >
                Logout
              </button>
            </div>
          </div>
        </div>
      </nav>

      <main className="mx-auto max-w-7xl px-4 py-8 sm:px-6 lg:px-8">
        <div className="mb-6 flex items-center justify-between">
          <h2 className="text-2xl font-bold text-zinc-900 dark:text-zinc-50">
            My Notes
          </h2>
          <button
            onClick={() => setShowCreateForm(!showCreateForm)}
            className="rounded-md bg-zinc-900 px-4 py-2 text-white hover:bg-zinc-800 dark:bg-zinc-50 dark:text-zinc-900 dark:hover:bg-zinc-200"
          >
            {showCreateForm ? 'Cancel' : 'New Note'}
          </button>
        </div>

        {error && (
          <div className="mb-4 rounded-md bg-red-50 p-4 text-red-800 dark:bg-red-900/20 dark:text-red-200">
            {error}
          </div>
        )}

        {showCreateForm && (
          <form
            onSubmit={handleCreateNote}
            className="mb-8 rounded-lg border border-zinc-200 bg-white p-6 dark:border-zinc-800 dark:bg-zinc-900"
          >
            <div className="space-y-4">
              <div>
                <label className="block text-sm font-medium text-zinc-700 dark:text-zinc-300">
                  Title
                </label>
                <input
                  type="text"
                  value={newTitle}
                  onChange={(e) => setNewTitle(e.target.value)}
                  required
                  className="mt-1 block w-full rounded-md border border-zinc-300 bg-white px-3 py-2 text-zinc-900 shadow-sm focus:border-zinc-500 focus:outline-none focus:ring-zinc-500 dark:border-zinc-600 dark:bg-zinc-800 dark:text-zinc-50"
                />
              </div>
              <div>
                <label className="block text-sm font-medium text-zinc-700 dark:text-zinc-300">
                  Content
                </label>
                <textarea
                  value={newContent}
                  onChange={(e) => setNewContent(e.target.value)}
                  required
                  rows={4}
                  className="mt-1 block w-full rounded-md border border-zinc-300 bg-white px-3 py-2 text-zinc-900 shadow-sm focus:border-zinc-500 focus:outline-none focus:ring-zinc-500 dark:border-zinc-600 dark:bg-zinc-800 dark:text-zinc-50"
                />
              </div>
              <button
                type="submit"
                className="rounded-md bg-zinc-900 px-4 py-2 text-white hover:bg-zinc-800 dark:bg-zinc-50 dark:text-zinc-900 dark:hover:bg-zinc-200"
              >
                Create Note
              </button>
            </div>
          </form>
        )}

        <div className="grid gap-4 md:grid-cols-2 lg:grid-cols-3">
          {notes.map((note) => (
            <div
              key={note.id}
              className="rounded-lg border border-zinc-200 bg-white p-6 shadow-sm dark:border-zinc-800 dark:bg-zinc-900"
            >
              <h3 className="mb-2 text-lg font-semibold text-zinc-900 dark:text-zinc-50">
                {note.title}
              </h3>
              <p className="mb-4 text-sm text-zinc-600 dark:text-zinc-400 line-clamp-3">
                {note.content}
              </p>
              <div className="flex gap-2">
                <button
                  onClick={() => handleViewNote(note.id)}
                  className="rounded-md bg-zinc-100 px-3 py-1 text-sm text-zinc-900 hover:bg-zinc-200 dark:bg-zinc-800 dark:text-zinc-50 dark:hover:bg-zinc-700"
                >
                  View
                </button>
                <button
                  onClick={() => handleDeleteNote(note.id)}
                  className="rounded-md bg-red-100 px-3 py-1 text-sm text-red-900 hover:bg-red-200 dark:bg-red-900/20 dark:text-red-200 dark:hover:bg-red-900/30"
                >
                  Delete
                </button>
              </div>
            </div>
          ))}
        </div>

        {notes.length === 0 && !showCreateForm && (
          <div className="text-center text-zinc-600 dark:text-zinc-400">
            No notes yet. Create your first note!
          </div>
        )}
      </main>
    </div>
  )
}
