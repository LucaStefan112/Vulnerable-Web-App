import { NextRequest, NextResponse } from 'next/server'
import { readdir } from 'fs/promises'
import { join } from 'path'
import { existsSync } from 'fs'

// INTENTIONALLY VULNERABLE: Directory listing without authentication
// This allows anyone to see all uploaded files
export async function GET(request: NextRequest) {
  try {
    const uploadsDir = join(process.cwd(), 'public', 'uploads')
    
    if (!existsSync(uploadsDir)) {
      return NextResponse.json({
        message: 'No uploads directory',
        files: [],
      })
    }

    // INTENTIONALLY VULNERABLE: No authentication check
    // INTENTIONALLY VULNERABLE: Directory listing exposed
    const files = await readdir(uploadsDir)
    
    // Filter out .gitkeep and other hidden files
    const publicFiles = files.filter(file => !file.startsWith('.'))

    // Return list of files with URLs
    const fileList = publicFiles.map(filename => ({
      filename,
      url: `/uploads/${filename}`,
    }))

    // Check if client wants JSON (API request) or HTML (browser)
    const acceptHeader = request.headers.get('accept') || ''
    if (acceptHeader.includes('application/json')) {
      return NextResponse.json({
        message: 'Uploaded files',
        files: fileList,
        count: fileList.length,
      })
    }

    // Return HTML directory listing (intentionally vulnerable)
    const html = `
<!DOCTYPE html>
<html>
<head>
  <title>Uploaded Files - Intentionally Vulnerable Directory Listing</title>
  <style>
    body { font-family: system-ui; padding: 2rem; max-width: 800px; margin: 0 auto; }
    h1 { color: #dc2626; }
    .warning { background: #fef3c7; padding: 1rem; border-radius: 0.5rem; margin: 1rem 0; }
    ul { list-style: none; padding: 0; }
    li { padding: 0.5rem; border-bottom: 1px solid #e5e7eb; }
    a { color: #2563eb; text-decoration: none; }
    a:hover { text-decoration: underline; }
    .empty { color: #6b7280; font-style: italic; }
  </style>
</head>
<body>
  <h1>📁 Uploaded Files</h1>
  <div class="warning">
    ⚠️ <strong>Intentionally Vulnerable:</strong> Directory listing exposed without authentication
  </div>
  ${fileList.length === 0 ? (
    '<p class="empty">No files uploaded yet.</p>'
  ) : (
    `<p>Found ${fileList.length} file(s):</p>
    <ul>
      ${fileList.map(file => `
        <li>
          <a href="${file.url}" target="_blank">${file.filename}</a>
        </li>
      `).join('')}
    </ul>`
  )}
  <p style="margin-top: 2rem; color: #6b7280; font-size: 0.875rem;">
    <a href="/upload">Upload a file</a> | <a href="/">Home</a>
  </p>
</body>
</html>
    `.trim()

    return new NextResponse(html, {
      headers: {
        'Content-Type': 'text/html',
      },
    })
  } catch (error) {
    console.error('Directory listing error:', error)
    return NextResponse.json(
      { error: 'Internal server error' },
      { status: 500 }
    )
  }
}
