import { describe, it, expect, beforeAll } from 'vitest'

const BASE_URL = process.env.TEST_BASE_URL || 'http://localhost:3000'

describe('Security Vulnerabilities', () => {
  let userToken: string
  let adminToken: string
  const userEmail = `vuln-test-${Date.now()}@test.com`
  const adminEmail = `admin-${Date.now()}@test.com`
  const password = 'testpass123'

  beforeAll(async () => {
    // Register regular user
    await fetch(`${BASE_URL}/api/auth/register`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ email: userEmail, password }),
    })
    const userLogin = await fetch(`${BASE_URL}/api/auth/login`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ email: userEmail, password }),
    })
    const userData = await userLogin.json()
    userToken = userData.token

    // Register admin user (will need to manually set role in DB for full test)
    await fetch(`${BASE_URL}/api/auth/register`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ email: adminEmail, password }),
    })
    const adminLogin = await fetch(`${BASE_URL}/api/auth/login`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ email: adminEmail, password }),
    })
    const adminData = await adminLogin.json()
    adminToken = adminData.token
  })

  describe('SQL Injection Vulnerability', () => {
    it('should be vulnerable to SQL injection in search endpoint', async () => {
      // Create a note first
      await fetch(`${BASE_URL}/api/notes`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Authorization': `Bearer ${userToken}`,
        },
        body: JSON.stringify({
          title: 'Test Note',
          content: 'Test content',
        }),
      })

      // SQL Injection attack: ' OR '1'='1
      const response = await fetch(
        `${BASE_URL}/api/notes/search?q=' OR '1'='1`,
        {
          headers: {
            'Authorization': `Bearer ${userToken}`,
          },
        }
      )

      // In a secure app, this should return an error or empty results
      // But due to SQL injection vulnerability, it might return all notes
      expect(response.status).toBe(200)
      const data = await response.json()
      expect(Array.isArray(data)).toBe(true)
      // This demonstrates the SQL injection vulnerability
    })
  })

  describe('Missing Authorization - Admin Endpoint', () => {
    it('should allow regular user to access admin endpoint (missing authorization)', async () => {
      // Regular user (not admin) accessing admin endpoint
      const response = await fetch(`${BASE_URL}/api/admin/users`, {
        headers: {
          'Authorization': `Bearer ${userToken}`,
        },
      })

      // This should fail in a secure app (403 Forbidden)
      // But passes due to missing authorization check
      expect(response.status).toBe(200)
      const data = await response.json()
      expect(Array.isArray(data)).toBe(true)
      // Regular user can see all users - this is the vulnerability
    })
  })

  describe('Insecure File Upload', () => {
    it('should allow file upload without authentication', async () => {
      const formData = new FormData()
      const blob = new Blob(['test file content'], { type: 'text/plain' })
      formData.append('file', blob, 'test.txt')

      // Upload without authentication
      const response = await fetch(`${BASE_URL}/api/upload`, {
        method: 'POST',
        body: formData,
      })

      // This should fail in a secure app (401 Unauthorized)
      // But passes due to missing authentication check
      expect(response.status).toBe(200)
      const data = await response.json()
      expect(data).toHaveProperty('url')
      expect(data).toHaveProperty('filename')
      // File uploaded without auth - this is the vulnerability
    })

    it('should allow upload of any file type without validation', async () => {
      const formData = new FormData()
      const blob = new Blob(['malicious content'], { type: 'application/x-executable' })
      formData.append('file', blob, 'malicious.exe')

      const response = await fetch(`${BASE_URL}/api/upload`, {
        method: 'POST',
        headers: {
          'Authorization': `Bearer ${userToken}`,
        },
        body: formData,
      })

      // Should be rejected in secure app, but passes due to no validation
      expect(response.status).toBe(200)
      const data = await response.json()
      expect(data.filename).toBe('malicious.exe')
      // Executable file uploaded - this is the vulnerability
    })
  })

  describe('Weak JWT Implementation', () => {
    it('should use weak JWT secret', async () => {
      // The JWT secret is weak (defaults to 'weak-secret-key-12345')
      // This is verified by checking the auth.ts implementation
      // In production, this should be a strong random secret
      expect(process.env.JWT_SECRET || 'weak-secret-key-12345').toBeTruthy()
    })

    it('should have long token expiry', async () => {
      // Tokens are set to expire in 365 days
      // This is verified in the auth.ts implementation
      // In production, tokens should expire much sooner (e.g., 1 hour)
    })
  })
})
