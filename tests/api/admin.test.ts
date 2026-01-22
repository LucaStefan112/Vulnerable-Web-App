import { describe, it, expect, beforeAll } from 'vitest'

const BASE_URL = process.env.TEST_BASE_URL || 'http://localhost:3000'

describe('Admin Endpoints', () => {
  let regularUserToken: string
  const regularUserEmail = `regular-${Date.now()}@test.com`
  const password = 'testpass123'

  beforeAll(async () => {
    // Register and login regular user (not admin)
    await fetch(`${BASE_URL}/api/auth/register`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ email: regularUserEmail, password }),
    })
    const login = await fetch(`${BASE_URL}/api/auth/login`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ email: regularUserEmail, password }),
    })
    const loginData = await login.json()
    regularUserToken = loginData.token
  })

  describe('GET /api/admin/users', () => {
    it('should be accessible by regular users (missing authorization)', async () => {
      // Regular user accessing admin endpoint
      const response = await fetch(`${BASE_URL}/api/admin/users`, {
        headers: {
          'Authorization': `Bearer ${regularUserToken}`,
        },
      })

      // This should return 403 Forbidden in a secure app
      // But returns 200 due to missing role check
      expect(response.status).toBe(200)
      const data = await response.json()
      expect(Array.isArray(data)).toBe(true)
      expect(data.length).toBeGreaterThan(0)
      
      // Verify it returns user data
      const user = data.find((u: any) => u.email === regularUserEmail)
      expect(user).toBeDefined()
      expect(user).toHaveProperty('id')
      expect(user).toHaveProperty('email')
      expect(user).toHaveProperty('role')
    })

    it('should return sensitive user information', async () => {
      const response = await fetch(`${BASE_URL}/api/admin/users`, {
        headers: {
          'Authorization': `Bearer ${regularUserToken}`,
        },
      })

      const data = await response.json()
      // Should not expose all users to regular users
      // But does due to missing authorization
      expect(data.length).toBeGreaterThan(0)
      data.forEach((user: any) => {
        expect(user).toHaveProperty('email')
        expect(user).toHaveProperty('role')
        expect(user).toHaveProperty('createdAt')
      })
    })
  })
})
