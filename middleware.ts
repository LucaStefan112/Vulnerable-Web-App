import { NextResponse } from 'next/server'
import type { NextRequest } from 'next/server'
import { verifyToken, getTokenFromRequest } from '@/lib/auth'

// INTENTIONALLY VULNERABLE: Flawed JWT checks, incomplete authorization
export function middleware(request: NextRequest) {
  const { pathname } = request.nextUrl

  // Public routes that don't require authentication
  const publicRoutes = ['/login', '/register', '/']
  if (publicRoutes.some(route => pathname.startsWith(route))) {
    return NextResponse.next()
  }

  // API routes - check authentication
  if (pathname.startsWith('/api/')) {
    // Health check doesn't need auth
    if (pathname === '/api/health') {
      return NextResponse.next()
    }

    const token = getTokenFromRequest(request.headers)

    // INTENTIONALLY VULNERABLE: Some routes might not check auth properly
    if (!token) {
      // Some endpoints might allow unauthenticated access
      // This is intentionally inconsistent
      if (pathname.startsWith('/api/upload')) {
        // Upload might be accessible without auth (intentional vulnerability)
        return NextResponse.next()
      }
      
      return NextResponse.json(
        { error: 'Unauthorized' },
        { status: 401 }
      )
    }

    // Verify token
    try {
      const decoded = verifyToken(token)
      
      // INTENTIONALLY VULNERABLE: Admin routes might not check role
      if (pathname.startsWith('/api/admin')) {
        // Should check: if (decoded.role !== 'admin')
        // But we're intentionally not enforcing it in middleware
        // Relying on route handlers (which also don't check properly)
      }

      // Add user info to headers for downstream use
      const requestHeaders = new Headers(request.headers)
      requestHeaders.set('x-user-id', decoded.userId.toString())
      requestHeaders.set('x-user-email', decoded.email)
      requestHeaders.set('x-user-role', decoded.role)

      return NextResponse.next({
        request: {
          headers: requestHeaders,
        },
      })
    } catch (error) {
      // INTENTIONALLY VULNERABLE: Might allow some routes even with invalid token
      return NextResponse.json(
        { error: 'Invalid token' },
        { status: 401 }
      )
    }
  }

  // Frontend routes - check authentication
  const token = getTokenFromRequest(request.headers)
  
  if (!token) {
    // Redirect to login if not authenticated
    if (pathname.startsWith('/notes') || pathname.startsWith('/admin')) {
      return NextResponse.redirect(new URL('/login', request.url))
    }
  } else {
    // Verify token
    try {
      const decoded = verifyToken(token)
      
      // INTENTIONALLY VULNERABLE: Admin routes might not check role in middleware
      if (pathname.startsWith('/admin')) {
        // Should redirect if not admin, but we're not checking
      }
    } catch (error) {
      // Redirect to login on invalid token
      if (pathname.startsWith('/notes') || pathname.startsWith('/admin')) {
        return NextResponse.redirect(new URL('/login', request.url))
      }
    }
  }

  return NextResponse.next()
}

export const config = {
  matcher: [
    /*
     * Match all request paths except for the ones starting with:
     * - _next/static (static files)
     * - _next/image (image optimization files)
     * - favicon.ico (favicon file)
     * - public folder
     */
    '/((?!_next/static|_next/image|favicon.ico|.*\\.(?:svg|png|jpg|jpeg|gif|webp)$).*)',
  ],
}
