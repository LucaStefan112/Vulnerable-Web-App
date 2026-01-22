'use client'

import { useState, useEffect } from 'react'
import { useRouter } from 'next/navigation'
import Link from 'next/link'

interface User {
  id: number
  email: string
  role: string
  createdAt: string
  _count?: {
    notes: number
  }
}

export default function AdminPage() {
  const router = useRouter()
  const [users, setUsers] = useState<User[]>([])
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState('')
  const [user, setUser] = useState<any>(null)

  useEffect(() => {
    loadUser()
    loadUsers()
  }, [])

  const loadUser = async () => {
    try {
      const token = localStorage.getItem('token')
      if (!token) {
        router.push('/login')
        return
      }

      // INTENTIONALLY VULNERABLE: Client-side role check only
      const payload = JSON.parse(atob(token.split('.')[1]))
      setUser(payload)

      // INTENTIONALLY VULNERABLE: Should check role on server
      // This is only a client-side check
      if (payload.role !== 'admin') {
        // Still allow access - server should block but doesn't
        console.warn('Non-admin user accessing admin page')
      }
    } catch (err) {
      console.error('Error loading user:', err)
    }
  }

  const loadUsers = async () => {
    try {
      const token = localStorage.getItem('token')
      if (!token) {
        router.push('/login')
        return
      }

      // INTENTIONALLY VULNERABLE: No server-side role check
      const response = await fetch('/api/admin/users', {
        headers: {
          'Authorization': `Bearer ${token}`,
        },
      })

      if (!response.ok) {
        if (response.status === 401) {
          router.push('/login')
          return
        }
        throw new Error('Failed to load users')
      }

      const data = await response.json()
      setUsers(data)
      setLoading(false)
    } catch (err) {
      setError('Failed to load users')
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
                Admin Dashboard
              </h1>
            </div>
            <div className="flex items-center gap-4">
              {user && (
                <span className="text-sm text-zinc-600 dark:text-zinc-400">
                  {user.email} ({user.role})
                </span>
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
        <div className="mb-6">
          <h2 className="text-2xl font-bold text-zinc-900 dark:text-zinc-50">
            All Users
          </h2>
          <p className="mt-2 text-sm text-zinc-600 dark:text-zinc-400">
            ⚠️ Intentionally Vulnerable: Missing server-side role check. Any authenticated user can access this page.
          </p>
        </div>

        {error && (
          <div className="mb-4 rounded-md bg-red-50 p-4 text-red-800 dark:bg-red-900/20 dark:text-red-200">
            {error}
          </div>
        )}

        <div className="overflow-hidden rounded-lg border border-zinc-200 bg-white shadow dark:border-zinc-800 dark:bg-zinc-900">
          <table className="min-w-full divide-y divide-zinc-200 dark:divide-zinc-800">
            <thead className="bg-zinc-50 dark:bg-zinc-800">
              <tr>
                <th className="px-6 py-3 text-left text-xs font-medium uppercase tracking-wider text-zinc-500 dark:text-zinc-400">
                  ID
                </th>
                <th className="px-6 py-3 text-left text-xs font-medium uppercase tracking-wider text-zinc-500 dark:text-zinc-400">
                  Email
                </th>
                <th className="px-6 py-3 text-left text-xs font-medium uppercase tracking-wider text-zinc-500 dark:text-zinc-400">
                  Role
                </th>
                <th className="px-6 py-3 text-left text-xs font-medium uppercase tracking-wider text-zinc-500 dark:text-zinc-400">
                  Notes Count
                </th>
                <th className="px-6 py-3 text-left text-xs font-medium uppercase tracking-wider text-zinc-500 dark:text-zinc-400">
                  Created At
                </th>
              </tr>
            </thead>
            <tbody className="divide-y divide-zinc-200 bg-white dark:divide-zinc-800 dark:bg-zinc-900">
              {users.map((user) => (
                <tr key={user.id}>
                  <td className="whitespace-nowrap px-6 py-4 text-sm text-zinc-900 dark:text-zinc-50">
                    {user.id}
                  </td>
                  <td className="whitespace-nowrap px-6 py-4 text-sm text-zinc-900 dark:text-zinc-50">
                    {user.email}
                  </td>
                  <td className="whitespace-nowrap px-6 py-4 text-sm">
                    <span
                      className={`inline-flex rounded-full px-2 py-1 text-xs font-semibold ${
                        user.role === 'admin'
                          ? 'bg-purple-100 text-purple-800 dark:bg-purple-900/20 dark:text-purple-200'
                          : 'bg-zinc-100 text-zinc-800 dark:bg-zinc-800 dark:text-zinc-200'
                      }`}
                    >
                      {user.role}
                    </span>
                  </td>
                  <td className="whitespace-nowrap px-6 py-4 text-sm text-zinc-900 dark:text-zinc-50">
                    {user._count?.notes || 0}
                  </td>
                  <td className="whitespace-nowrap px-6 py-4 text-sm text-zinc-600 dark:text-zinc-400">
                    {new Date(user.createdAt).toLocaleString()}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>

        {users.length === 0 && (
          <div className="text-center text-zinc-600 dark:text-zinc-400">
            No users found.
          </div>
        )}
      </main>
    </div>
  )
}
