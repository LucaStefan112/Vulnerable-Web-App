import { beforeAll, afterAll, beforeEach } from 'vitest'
import { execSync } from 'child_process'

// Setup test environment
beforeAll(() => {
  // Set test environment variables
  process.env.DATABASE_URL = process.env.DATABASE_URL || 'postgresql://secureapp:secureapp@localhost:5433/secureapp?schema=public'
  process.env.JWT_SECRET = process.env.JWT_SECRET || 'test-secret-key'
  process.env.NODE_ENV = 'test'
})
