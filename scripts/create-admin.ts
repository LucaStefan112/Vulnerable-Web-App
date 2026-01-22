/**
 * Script to create an admin user
 * Run with: npx tsx scripts/create-admin.ts <email> <password>
 */

import prisma from '@/lib/prisma'
import bcrypt from 'bcrypt'

async function createAdmin() {
  const email = process.argv[2]
  const password = process.argv[3]

  if (!email || !password) {
    console.error('Usage: npx tsx scripts/create-admin.ts <email> <password>')
    process.exit(1)
  }

  try {
    // Check if user already exists
    const existingUser = await prisma.user.findUnique({
      where: { email },
    })

    if (existingUser) {
      // Update to admin
      const hashedPassword = await bcrypt.hash(password, 10)
      await prisma.user.update({
        where: { email },
        data: {
          password: hashedPassword,
          role: 'admin',
        },
      })
      console.log(`User ${email} updated to admin`)
    } else {
      // Create new admin user
      const hashedPassword = await bcrypt.hash(password, 10)
      await prisma.user.create({
        data: {
          email,
          password: hashedPassword,
          role: 'admin',
        },
      })
      console.log(`Admin user ${email} created successfully`)
    }
  } catch (error) {
    console.error('Error creating admin user:', error)
    process.exit(1)
  } finally {
    await prisma.$disconnect()
  }
}

createAdmin()
