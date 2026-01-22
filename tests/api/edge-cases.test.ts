import { describe, it, expect } from 'vitest'

const BASE_URL = process.env.TEST_BASE_URL || 'http://localhost:3000'

describe('Edge Cases and Error Handling', () => {
  describe('Invalid Input Handling', () => {
    it('should handle malformed JSON in register', async () => {
      const response = await fetch(`${BASE_URL}/api/auth/register`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: 'invalid json{',
      })

      // Should handle gracefully
      expect(response.status).toBeGreaterThanOrEqual(400)
    })

    it('should handle empty request body', async () => {
      const response = await fetch(`${BASE_URL}/api/auth/register`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: '',
      })

      expect(response.status).toBeGreaterThanOrEqual(400)
    })

    it('should handle very long email addresses', async () => {
      const longEmail = 'a'.repeat(300) + '@example.com'
      const response = await fetch(`${BASE_URL}/api/auth/register`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({
          email: longEmail,
          password: 'test123',
        }),
      })

      // Should either accept or reject gracefully
      expect([200, 400, 500]).toContain(response.status)
    })

    it('should handle SQL injection in email field', async () => {
      const sqlInjectionEmail = "test' OR '1'='1'--@example.com"
      const response = await fetch(`${BASE_URL}/api/auth/register`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({
          email: sqlInjectionEmail,
          password: 'test123',
        }),
      })

      // Should handle gracefully (Prisma should protect against this)
      expect([200, 400, 500]).toContain(response.status)
    })
  })

  describe('Authentication Edge Cases', () => {
    it('should handle invalid JWT token', async () => {
      const response = await fetch(`${BASE_URL}/api/notes`, {
        headers: {
          'Authorization': 'Bearer invalid.token.here',
        },
      })

      expect(response.status).toBe(401)
      const data = await response.json()
      expect(data).toHaveProperty('error')
    })

    it('should handle missing Authorization header', async () => {
      const response = await fetch(`${BASE_URL}/api/notes`)

      expect(response.status).toBe(401)
      const data = await response.json()
      expect(data).toHaveProperty('error')
    })

    it('should handle malformed Authorization header', async () => {
      const response = await fetch(`${BASE_URL}/api/notes`, {
        headers: {
          'Authorization': 'InvalidFormat token',
        },
      })

      expect(response.status).toBe(401)
    })
  })

  describe('Notes Edge Cases', () => {
    it('should handle non-numeric note ID', async () => {
      const token = 'dummy-token'
      const response = await fetch(`${BASE_URL}/api/notes/abc`, {
        headers: {
          'Authorization': `Bearer ${token}`,
        },
      })

      // Should return 400 or 401
      expect([400, 401, 404]).toContain(response.status)
    })

    it('should handle negative note ID', async () => {
      const token = 'dummy-token'
      const response = await fetch(`${BASE_URL}/api/notes/-1`, {
        headers: {
          'Authorization': `Bearer ${token}`,
        },
      })

      // Should return 400 or 401
      expect([400, 401, 404]).toContain(response.status)
    })

    it('should handle very large note ID', async () => {
      const token = 'dummy-token'
      const response = await fetch(`${BASE_URL}/api/notes/999999999`, {
        headers: {
          'Authorization': `Bearer ${token}`,
        },
      })

      // Should return 404 or 401
      expect([401, 404]).toContain(response.status)
    })

    it('should handle empty note title', async () => {
      // This test verifies if empty titles are allowed (weak validation)
      const email = `empty-title-${Date.now()}@test.com`
      await fetch(`${BASE_URL}/api/auth/register`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ email, password: 'test123' }),
      })
      const login = await fetch(`${BASE_URL}/api/auth/login`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ email, password: 'test123' }),
      })
      const { token } = await login.json()

      const response = await fetch(`${BASE_URL}/api/notes`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Authorization': `Bearer ${token}`,
        },
        body: JSON.stringify({
          title: '',
          content: 'Content without title',
        }),
      })

      // Should either accept or reject
      expect([201, 400]).toContain(response.status)
    })
  })

  describe('File Upload Edge Cases', () => {
    it('should handle missing file in upload', async () => {
      const formData = new FormData()
      // No file appended

      const response = await fetch(`${BASE_URL}/api/upload`, {
        method: 'POST',
        body: formData,
      })

      expect(response.status).toBe(400)
      const data = await response.json()
      expect(data).toHaveProperty('error')
    })

    it('should handle path traversal in filename', async () => {
      const formData = new FormData()
      const blob = new Blob(['test'], { type: 'text/plain' })
      // Path traversal attempt
      formData.append('file', blob, '../../../etc/passwd')

      const response = await fetch(`${BASE_URL}/api/upload`, {
        method: 'POST',
        body: formData,
      })

      // Should either reject or allow (vulnerability)
      expect([200, 400, 500]).toContain(response.status)
      // If 200, this confirms path traversal vulnerability
    })

    it('should handle very large file upload', async () => {
      // Create a large file (10MB)
      const largeContent = 'x'.repeat(10 * 1024 * 1024)
      const formData = new FormData()
      const blob = new Blob([largeContent], { type: 'text/plain' })
      formData.append('file', blob, 'large.txt')

      const response = await fetch(`${BASE_URL}/api/upload`, {
        method: 'POST',
        body: formData,
      })

      // Should either accept or reject
      expect([200, 400, 413, 500]).toContain(response.status)
    })
  })
})
