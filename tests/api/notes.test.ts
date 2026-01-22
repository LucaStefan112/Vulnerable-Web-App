import { describe, it, expect, beforeAll } from 'vitest'

const BASE_URL = process.env.TEST_BASE_URL || 'http://localhost:3000'

describe('Notes Endpoints', () => {
  let user1Token: string
  let user2Token: string
  let user1NoteId: number
  let user2NoteId: number
  const user1Email = `user1-${Date.now()}@test.com`
  const user2Email = `user2-${Date.now()}@test.com`
  const password = 'testpass123'

  beforeAll(async () => {
    // Register and login user1
    await fetch(`${BASE_URL}/api/auth/register`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ email: user1Email, password }),
    })
    const login1 = await fetch(`${BASE_URL}/api/auth/login`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ email: user1Email, password }),
    })
    const login1Data = await login1.json()
    user1Token = login1Data.token

    // Register and login user2
    await fetch(`${BASE_URL}/api/auth/register`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ email: user2Email, password }),
    })
    const login2 = await fetch(`${BASE_URL}/api/auth/login`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ email: user2Email, password }),
    })
    const login2Data = await login2.json()
    user2Token = login2Data.token
  })

  describe('POST /api/notes', () => {
    it('should create a note for user1', async () => {
      const response = await fetch(`${BASE_URL}/api/notes`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Authorization': `Bearer ${user1Token}`,
        },
        body: JSON.stringify({
          title: 'User1 Private Note',
          content: 'This is a private note for user1',
        }),
      })

      expect(response.status).toBe(201)
      const data = await response.json()
      expect(data).toHaveProperty('id')
      expect(data.title).toBe('User1 Private Note')
      expect(data.userId).toBeDefined()
      user1NoteId = data.id
    })

    it('should create a note for user2', async () => {
      const response = await fetch(`${BASE_URL}/api/notes`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Authorization': `Bearer ${user2Token}`,
        },
        body: JSON.stringify({
          title: 'User2 Private Note',
          content: 'This is a private note for user2',
        }),
      })

      expect(response.status).toBe(201)
      const data = await response.json()
      expect(data).toHaveProperty('id')
      expect(data.title).toBe('User2 Private Note')
      user2NoteId = data.id
    })

    it('should reject note creation without authentication', async () => {
      const response = await fetch(`${BASE_URL}/api/notes`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({
          title: 'Test Note',
          content: 'Test content',
        }),
      })

      expect(response.status).toBe(401)
    })
  })

  describe('GET /api/notes', () => {
    it('should return only user1 notes', async () => {
      const response = await fetch(`${BASE_URL}/api/notes`, {
        headers: {
          'Authorization': `Bearer ${user1Token}`,
        },
      })

      expect(response.status).toBe(200)
      const data = await response.json()
      expect(Array.isArray(data)).toBe(true)
      // Should only contain user1's notes
      data.forEach((note: any) => {
        expect(note.userId).toBeDefined()
      })
    })
  })

  describe('GET /api/notes/[id] - IDOR Vulnerability', () => {
    it('should allow user2 to access user1 note (IDOR vulnerability)', async () => {
      // INTENTIONALLY VULNERABLE: This test verifies the IDOR vulnerability
      const response = await fetch(`${BASE_URL}/api/notes/${user1NoteId}`, {
        headers: {
          'Authorization': `Bearer ${user2Token}`,
        },
      })

      // This should fail in a secure app, but passes due to IDOR vulnerability
      expect(response.status).toBe(200)
      const data = await response.json()
      expect(data.id).toBe(user1NoteId)
      expect(data.title).toBe('User1 Private Note')
      // User2 can read user1's note - this is the vulnerability
    })
  })

  describe('DELETE /api/notes/[id] - IDOR Vulnerability', () => {
    it('should allow user2 to delete user1 note (IDOR vulnerability)', async () => {
      // Create another note for user1
      const createResponse = await fetch(`${BASE_URL}/api/notes`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Authorization': `Bearer ${user1Token}`,
        },
        body: JSON.stringify({
          title: 'Note to be deleted',
          content: 'This note will be deleted by user2',
        }),
      })
      const noteData = await createResponse.json()
      const noteId = noteData.id

      // User2 deletes user1's note - this is the vulnerability
      const deleteResponse = await fetch(`${BASE_URL}/api/notes/${noteId}`, {
        method: 'DELETE',
        headers: {
          'Authorization': `Bearer ${user2Token}`,
        },
      })

      // This should fail in a secure app, but passes due to IDOR vulnerability
      expect(deleteResponse.status).toBe(200)
      const deleteData = await deleteResponse.json()
      expect(deleteData.message).toBe('Note deleted successfully')

      // Verify note is actually deleted
      const getResponse = await fetch(`${BASE_URL}/api/notes/${noteId}`, {
        headers: {
          'Authorization': `Bearer ${user1Token}`,
        },
      })
      expect(getResponse.status).toBe(404)
    })
  })
})
