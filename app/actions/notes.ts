'use server'

import prisma from '@/lib/prisma'
import { cookies } from 'next/headers'
import { verifyToken } from '@/lib/auth'

// INTENTIONALLY VULNERABLE: Server Actions with authorization bypass
// Server Actions can be called directly without proper auth checks

export async function createNote(title: string, content: string) {
  // INTENTIONALLY VULNERABLE: Auth check might be missing or incomplete
  const cookieStore = await cookies()
  const token = cookieStore.get('token')?.value

  if (!token) {
    throw new Error('Unauthorized')
  }

  try {
    const decoded = verifyToken(token)
    
    const note = await prisma.note.create({
      data: {
        title,
        content,
        userId: decoded.userId,
      },
    })

    return note
    } catch {
      throw new Error('Failed to create note')
    }
}

export async function deleteNote(noteId: number) {
  // INTENTIONALLY VULNERABLE: No ownership check
  const cookieStore = await cookies()
  const token = cookieStore.get('token')?.value

  if (!token) {
    throw new Error('Unauthorized')
  }

    try {
      // INTENTIONALLY VULNERABLE: No check if note belongs to user
      await prisma.note.delete({
        where: { id: noteId },
      })

      return { success: true }
    } catch {
      throw new Error('Failed to delete note')
    }
}

export async function getAllUsers() {
  // INTENTIONALLY VULNERABLE: No role check - any user can call this
  const cookieStore = await cookies()
  const token = cookieStore.get('token')?.value

  if (!token) {
    throw new Error('Unauthorized')
  }

  try {
    // INTENTIONALLY VULNERABLE: Should check if user is admin
    // But we're not checking role here
    const users = await prisma.user.findMany({
      select: {
        id: true,
        email: true,
        role: true,
        createdAt: true,
      },
    })

    return users
    } catch {
      throw new Error('Failed to get users')
    }
}
