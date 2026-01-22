import { NextRequest, NextResponse } from 'next/server'
import prisma from '@/lib/prisma'
import { getTokenFromRequest, verifyToken } from '@/lib/auth'

// GET /api/notes/[id] - Get a specific note
// INTENTIONALLY VULNERABLE: IDOR - No ownership validation
export async function GET(
  request: NextRequest,
  { params }: { params: Promise<{ id: string }> }
) {
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

    const { id } = await params
    const noteId = parseInt(id)

    if (isNaN(noteId)) {
      return NextResponse.json(
        { error: 'Invalid note ID' },
        { status: 400 }
      )
    }

    // INTENTIONALLY VULNERABLE: No ownership check
    // Any authenticated user can access any note by ID
    const note = await prisma.note.findUnique({
      where: { id: noteId },
      include: {
        user: {
          select: {
            email: true,
          },
        },
      },
    })

    if (!note) {
      return NextResponse.json(
        { error: 'Note not found' },
        { status: 404 }
      )
    }

    // No check: if (note.userId !== decoded.userId)
    // This allows any user to read any note

    return NextResponse.json(note)
  } catch (error) {
    console.error('Get note error:', error)
    return NextResponse.json(
      { error: 'Internal server error' },
      { status: 500 }
    )
  }
}

// DELETE /api/notes/[id] - Delete a note
// INTENTIONALLY VULNERABLE: IDOR - No authorization check
export async function DELETE(
  request: NextRequest,
  { params }: { params: Promise<{ id: string }> }
) {
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

    const { id } = await params
    const noteId = parseInt(id)

    if (isNaN(noteId)) {
      return NextResponse.json(
        { error: 'Invalid note ID' },
        { status: 400 }
      )
    }

    // INTENTIONALLY VULNERABLE: No ownership check before delete
    // Any authenticated user can delete any note
    const note = await prisma.note.delete({
      where: { id: noteId },
    })

    // No check: if (note.userId !== decoded.userId)
    // This allows any user to delete any note

    return NextResponse.json({ message: 'Note deleted successfully' })
  } catch (error: any) {
    // INTENTIONALLY VULNERABLE: Verbose error messages
    if (error.code === 'P2025') {
      return NextResponse.json(
        { error: 'Note not found' },
        { status: 404 }
      )
    }
    console.error('Delete note error:', error)
    return NextResponse.json(
      { error: 'Internal server error' },
      { status: 500 }
    )
  }
}
