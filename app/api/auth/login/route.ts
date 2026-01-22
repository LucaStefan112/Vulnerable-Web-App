import { NextRequest, NextResponse } from 'next/server'
import bcrypt from 'bcrypt'
import prisma from '@/lib/prisma'
import { signToken } from '@/lib/auth'

// INTENTIONALLY VULNERABLE: No rate limiting, verbose error messages
export async function POST(request: NextRequest) {
  try {
    const body = await request.json()
    const { email, password } = body

    if (!email || !password) {
      return NextResponse.json(
        { error: 'Email and password are required' },
        { status: 400 }
      )
    }

    // Find user
    const user = await prisma.user.findUnique({
      where: { email },
    })

    // INTENTIONALLY VULNERABLE: Verbose error messages help attackers
    if (!user) {
      return NextResponse.json(
        { error: 'Invalid email or password' }, // Should be generic
        { status: 401 }
      )
    }

    // Verify password
    const isValid = await bcrypt.compare(password, user.password)

    if (!isValid) {
      return NextResponse.json(
        { error: 'Invalid email or password' },
        { status: 401 }
      )
    }

    // Generate token with intentionally weak configuration
    const token = signToken({
      userId: user.id,
      email: user.email,
      role: user.role,
    })

    // Set cookie (intentionally not HttpOnly)
    const response = NextResponse.json({
      token, // Return token in response body
      user: {
        id: user.id,
        email: user.email,
        role: user.role,
      },
    })

    response.cookies.set('token', token, {
      httpOnly: false, // INTENTIONALLY INSECURE
      secure: false, // INTENTIONALLY INSECURE
      sameSite: 'lax',
      maxAge: 60 * 60 * 24 * 365, // 365 days
    })

    return response
  } catch (error) {
    console.error('Login error:', error)
    return NextResponse.json(
      { error: 'Internal server error' },
      { status: 500 }
    )
  }
}
