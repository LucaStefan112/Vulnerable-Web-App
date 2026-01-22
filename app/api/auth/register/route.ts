import { NextRequest, NextResponse } from 'next/server'
import bcrypt from 'bcrypt'
import prisma from '@/lib/prisma'
import { signToken } from '@/lib/auth'

// INTENTIONALLY VULNERABLE: Weak password requirements, no email verification
export async function POST(request: NextRequest) {
  try {
    const body = await request.json()
    const { email, password } = body

    // Weak validation - only checks if fields exist
    if (!email || !password) {
      return NextResponse.json(
        { error: 'Email and password are required' },
        { status: 400 }
      )
    }

    // INTENTIONALLY WEAK: No password strength requirements
    // No email validation
    // No rate limiting
    // No email verification

    // Check if user already exists
    const existingUser = await prisma.user.findUnique({
      where: { email },
    })

    if (existingUser) {
      return NextResponse.json(
        { error: 'User already exists' },
        { status: 400 }
      )
    }

    // Hash password (this is actually secure, but we'll have weak JWT)
    const hashedPassword = await bcrypt.hash(password, 10)

    // Create user
    const user = await prisma.user.create({
      data: {
        email,
        password: hashedPassword,
        role: 'user', // Default role
      },
    })

    // Generate token with intentionally weak configuration
    const token = signToken({
      userId: user.id,
      email: user.email,
      role: user.role,
    })

    // Set cookie (intentionally not HttpOnly for demo purposes)
    const response = NextResponse.json({
      message: 'User registered successfully',
      token, // Also return in body (intentionally insecure)
    })

    response.cookies.set('token', token, {
      httpOnly: false, // INTENTIONALLY INSECURE: Should be true
      secure: false, // INTENTIONALLY INSECURE: Should be true in production
      sameSite: 'lax',
      maxAge: 60 * 60 * 24 * 365, // 365 days
    })

    return response
  } catch (error) {
    console.error('Registration error:', error)
    return NextResponse.json(
      { error: 'Internal server error' },
      { status: 500 }
    )
  }
}
