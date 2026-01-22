import type { Metadata } from 'next'
import './globals.css'

export const metadata: Metadata = {
  title: 'SecureNotes - Intentionally Vulnerable App',
  description: 'An intentionally vulnerable Next.js application for security research',
}

export default function RootLayout({
  children,
}: {
  children: React.ReactNode
}) {
  return (
    <html lang="en">
      <body className="antialiased">{children}</body>
    </html>
  )
}
