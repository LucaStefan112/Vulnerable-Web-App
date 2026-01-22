import { describe, it, expect, beforeEach } from 'vitest'

const BASE_URL = process.env.TEST_BASE_URL || 'http://localhost:3000'

describe('Authentication Endpoints', () => {
  const testEmail = `test-${Date.now()}@example.com`
  const testPassword = 'testpassword123'
  let authToken: string

  describe('POST /api/auth/register', () => {
    it('should register a new user successfully', async () => {
      const response = await fetch(`${BASE_URL}/api/auth/register`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({
          email: testEmail,
          password: testPassword,
        }),
      })

      expect(response.status).toBe(200)
      const data = await response.json()
      expect(data).toHaveProperty('message')
      expect(data).toHaveProperty('token')
      expect(data.message).toBe('User registered successfully')
      expect(typeof data.token).toBe('string')
      authToken = data.token
    })

    it('should reject registration with missing email', async () => {
      const response = await fetch(`${BASE_URL}/api/auth/register`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({
          password: testPassword,
        }),
      })

      expect(response.status).toBe(400)
      const data = await response.json()
      expect(data).toHaveProperty('error')
    })

    it('should reject registration with missing password', async () => {
      const response = await fetch(`${BASE_URL}/api/auth/register`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({
          email: testEmail,
        }),
      })

      expect(response.status).toBe(400)
      const data = await response.json()
      expect(data).toHaveProperty('error')
    })

    it('should reject duplicate email registration', async () => {
      const response = await fetch(`${BASE_URL}/api/auth/register`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({
          email: testEmail,
          password: testPassword,
        }),
      })

      expect(response.status).toBe(400)
      const data = await response.json()
      expect(data).toHaveProperty('error')
      expect(data.error).toBe('User already exists')
    })
  })

  describe('POST /api/auth/login', () => {
    it('should login with valid credentials', async () => {
      const response = await fetch(`${BASE_URL}/api/auth/login`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({
          email: testEmail,
          password: testPassword,
        }),
      })

      expect(response.status).toBe(200)
      const data = await response.json()
      expect(data).toHaveProperty('token')
      expect(data).toHaveProperty('user')
      expect(data.user.email).toBe(testEmail)
      authToken = data.token
    })

    it('should reject login with wrong password', async () => {
      const response = await fetch(`${BASE_URL}/api/auth/login`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({
          email: testEmail,
          password: 'wrongpassword',
        }),
      })

      expect(response.status).toBe(401)
      const data = await response.json()
      expect(data).toHaveProperty('error')
    })

    it('should reject login with non-existent email', async () => {
      const response = await fetch(`${BASE_URL}/api/auth/login`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({
          email: 'nonexistent@example.com',
          password: testPassword,
        }),
      })

      expect(response.status).toBe(401)
      const data = await response.json()
      expect(data).toHaveProperty('error')
    })
  })
})
