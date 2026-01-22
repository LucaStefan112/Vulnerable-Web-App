import jwt from 'jsonwebtoken'

// INTENTIONALLY WEAK: Static secret, no algorithm enforcement
// In production, this should be a strong random secret from environment variables
const JWT_SECRET = process.env.JWT_SECRET || 'weak-secret-key-12345'

export interface JWTPayload {
  userId: number
  email: string
  role: string
}

// INTENTIONALLY VULNERABLE: Weak secret, long expiry, no algorithm specified
export function signToken(payload: JWTPayload): string {
  // No algorithm specified - allows algorithm confusion attacks
  // Long expiry (365 days) - tokens never expire
  return jwt.sign(payload, JWT_SECRET, {
    expiresIn: '365d', // Intentionally long-lived
    // Missing: algorithm: 'HS256' - allows algorithm confusion
  })
}

// INTENTIONALLY VULNERABLE: No algorithm verification
export function verifyToken(token: string): JWTPayload {
  // No algorithm specified - accepts any algorithm
  // This allows algorithm confusion attacks (e.g., 'none' algorithm)
  const decoded = jwt.verify(token, JWT_SECRET) as JWTPayload
  return decoded
}

// Helper to extract token from Authorization header or cookies
export function getTokenFromRequest(headers: Headers): string | null {
  // Check Authorization header
  const authHeader = headers.get('authorization')
  if (authHeader?.startsWith('Bearer ')) {
    return authHeader.substring(7)
  }
  
  // Check cookies (intentionally insecure - should be HttpOnly in production)
  const cookieHeader = headers.get('cookie')
  if (cookieHeader) {
    const cookies = cookieHeader.split(';').map(c => c.trim())
    const tokenCookie = cookies.find(c => c.startsWith('token='))
    if (tokenCookie) {
      return tokenCookie.substring(6)
    }
  }
  
  return null
}
