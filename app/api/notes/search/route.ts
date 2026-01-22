import { NextRequest, NextResponse } from 'next/server'
import prisma from '@/lib/prisma'
import { getTokenFromRequest, verifyToken } from '@/lib/auth'

// INTENTIONALLY VULNERABLE: SQL Injection via raw query
// This endpoint demonstrates unsafe SQL query construction
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

    const searchParams = request.nextUrl.searchParams
    const searchTerm = searchParams.get('q') || ''

    // INTENTIONALLY VULNERABLE: Direct string interpolation in SQL
    // This allows SQL injection attacks
    // Example attack: ?q=' OR '1'='1
    // Example attack: ?q='; DROP TABLE users; --
    
    // Using Prisma's raw query with unsafe string interpolation
    const notes = await prisma.$queryRawUnsafe(`
      SELECT * FROM "Note" 
      WHERE "title" LIKE '%${searchTerm}%' 
      OR "content" LIKE '%${searchTerm}%'
      ORDER BY "createdAt" DESC
    `)

    return NextResponse.json(notes)
  } catch (error) {
    // INTENTIONALLY VULNERABLE: Verbose error messages expose database structure
    console.error('Search error:', error)
    return NextResponse.json(
      { 
        error: 'Internal server error',
        // In production, never expose error details
        details: error instanceof Error ? error.message : 'Unknown error'
      },
      { status: 500 }
    )
  }
}
