'use client'

import { useState, useEffect } from 'react'
import { useRouter, useParams } from 'next/navigation'
import Link from 'next/link'

interface Note {
  id: number
  title: string
  content: string
  userId: number
  createdAt: string
  updatedAt: string
  user?: {
    email: string
  }
}

export default function NoteDetailPage() {
  const router = useRouter()
  const params = useParams()
  const [note, setNote] = useState<Note | null>(null)
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState('')

  useEffect(() => {
    loadNote()
  }, [params.id])

  const loadNote = async () => {
    try {
      const token = localStorage.getItem('token')
      if (!token) {
        router.push('/login')
        return
      }

      // INTENTIONALLY VULNERABLE: Can access any note by ID (IDOR)
      const response = await fetch(`/api/notes/${params.id}`, {
        headers: {
          'Authorization': `Bearer ${token}`,
        },
      })

      if (!response.ok) {
        if (response.status === 401) {
          router.push('/login')
          return
        }
        throw new Error('Failed to load note')
      }

      const data = await response.json()
      setNote(data)
      setLoading(false)
    } catch (err) {
      setError('Failed to load note')
      setLoading(false)
    }
  }

  if (loading) {
    return (
      <div className="flex min-h-screen items-center justify-center">
        <div className="text-lg">Loading...</div>
      </div>
    )
  }

  if (error || !note) {
    return (
      <div className="flex min-h-screen items-center justify-center">
        <div className="text-lg text-red-600">{error || 'Note not found'}</div>
      </div>
    )
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
            </div>
          </div>
        </div>
      </nav>

      <main className="mx-auto max-w-4xl px-4 py-8 sm:px-6 lg:px-8">
        <div className="rounded-lg border border-zinc-200 bg-white p-8 shadow-sm dark:border-zinc-800 dark:bg-zinc-900">
          <div className="mb-4 flex items-center justify-between">
            <h1 className="text-3xl font-bold text-zinc-900 dark:text-zinc-50">
              {note.title}
            </h1>
            {note.user && (
              <span className="text-sm text-zinc-500 dark:text-zinc-400">
                By: {note.user.email}
              </span>
            )}
          </div>
          <div className="mb-4 text-sm text-zinc-500 dark:text-zinc-400">
            Created: {new Date(note.createdAt).toLocaleString()}
          </div>
          <div className="prose prose-zinc dark:prose-invert">
            <p className="whitespace-pre-wrap text-zinc-700 dark:text-zinc-300">
              {note.content}
            </p>
          </div>
          <div className="mt-6 text-xs text-yellow-600 dark:text-yellow-400">
            ⚠️ IDOR Vulnerability: This note may belong to another user. No ownership validation is performed.
          </div>
        </div>
      </main>
    </div>
  )
}
