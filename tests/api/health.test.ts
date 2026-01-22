import { describe, it, expect } from 'vitest'

const BASE_URL = process.env.TEST_BASE_URL || 'http://localhost:3000'

describe('Health Endpoint', () => {
  it('should return status ok', async () => {
    const response = await fetch(`${BASE_URL}/api/health`)
    expect(response.status).toBe(200)
    
    const data = await response.json()
    expect(data).toHaveProperty('status')
    expect(data.status).toBe('ok')
  })
})
