import { NextRequest, NextResponse } from 'next/server'
import { writeFile } from 'fs/promises'
import { join } from 'path'
import { existsSync, mkdirSync } from 'fs'

// INTENTIONALLY VULNERABLE: No file validation, public directory
export async function POST(request: NextRequest) {
  try {
    const formData = await request.formData()
    const file = formData.get('file') as File

    if (!file) {
      return NextResponse.json(
        { error: 'No file provided' },
        { status: 400 }
      )
    }

    // INTENTIONALLY VULNERABLE: No MIME type validation
    // INTENTIONALLY VULNERABLE: No file extension validation
    // INTENTIONALLY VULNERABLE: No file size limits
    // INTENTIONALLY VULNERABLE: No virus scanning

    const bytes = await file.arrayBuffer()
    const buffer = Buffer.from(bytes)

    // Create uploads directory if it doesn't exist
    const uploadsDir = join(process.cwd(), 'public', 'uploads')
    if (!existsSync(uploadsDir)) {
      mkdirSync(uploadsDir, { recursive: true })
    }

    // INTENTIONALLY VULNERABLE: Using original filename (path traversal risk)
    // INTENTIONALLY VULNERABLE: Files stored in public directory (accessible via URL)
    const filename = file.name
    const filepath = join(uploadsDir, filename)

    await writeFile(filepath, buffer)

    // Return public URL
    const publicUrl = `/uploads/${filename}`

    return NextResponse.json({
      message: 'File uploaded successfully',
      url: publicUrl,
      filename,
    })
  } catch (error) {
    console.error('Upload error:', error)
    return NextResponse.json(
      { error: 'Internal server error' },
      { status: 500 }
    )
  }
}
