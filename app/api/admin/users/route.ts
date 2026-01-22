import { NextRequest, NextResponse } from 'next/server'
import prisma from '@/lib/prisma'
import { getTokenFromRequest, verifyToken } from '@/lib/auth'

// GET /api/admin/users - Get all users
// INTENTIONALLY VULNERABLE: Missing or incomplete role check
export async function GET(request: NextRequest) {
  try {
    const token = getTokenFromRequest(request.headers)

    if (!token) {
      return NextResponse.json(
        { error: 'Unauthorized' },
        { status: 401 }
      )
    }

    // Verify token
    let decoded
    try {
      decoded = verifyToken(token)
    } catch (error) {
      return NextResponse.json(
        { error: 'Invalid token' },
        { status: 401 }
      )
    }

    // INTENTIONALLY VULNERABLE: Role check missing or incomplete
    // This should check: if (decoded.role !== 'admin')
    // But we're intentionally not checking it, or checking client-side only
    
    // Get all users (sensitive information)
    const users = await prisma.user.findMany({
      select: {
        id: true,
        email: true,
        role: true,
        createdAt: true,
        _count: {
          select: {
            notes: true,
          },
        },
      },
      orderBy: {
        createdAt: 'desc',
      },
    })

    return NextResponse.json(users)
  } catch (error) {
    console.error('Get users error:', error)
    return NextResponse.json(
      { error: 'Internal server error' },
      { status: 500 }
    )
  }
}
