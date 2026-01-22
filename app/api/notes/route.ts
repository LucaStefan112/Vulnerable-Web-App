import { NextRequest, NextResponse } from 'next/server'
import prisma from '@/lib/prisma'
import { getTokenFromRequest, verifyToken } from '@/lib/auth'

// GET /api/notes - Get all notes for authenticated user
export async function GET(request: NextRequest) {
  try {
    const token = getTokenFromRequest(request.headers)

    if (!token) {
      return NextResponse.json(
        { error: 'Unauthorized' },
        { status: 401 }
      )
    }

    // Verify token (intentionally weak verification)
    let decoded
    try {
      decoded = verifyToken(token)
    } catch (error) {
      return NextResponse.json(
        { error: 'Invalid token' },
        { status: 401 }
      )
    }

    // Get user's notes
    const notes = await prisma.note.findMany({
      where: {
        userId: decoded.userId,
      },
      orderBy: {
        createdAt: 'desc',
      },
    })

    return NextResponse.json(notes)
  } catch (error) {
    console.error('Get notes error:', error)
    return NextResponse.json(
      { error: 'Internal server error' },
      { status: 500 }
    )
  }
}

// POST /api/notes - Create a new note
export async function POST(request: NextRequest) {
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

    const body = await request.json()
    const { title, content } = body

    if (!title || !content) {
      return NextResponse.json(
        { error: 'Title and content are required' },
        { status: 400 }
      )
    }

    // Create note
    const note = await prisma.note.create({
      data: {
        title,
        content,
        userId: decoded.userId,
      },
    })

    return NextResponse.json(note, { status: 201 })
  } catch (error) {
    console.error('Create note error:', error)
    return NextResponse.json(
      { error: 'Internal server error' },
      { status: 500 }
    )
  }
}
