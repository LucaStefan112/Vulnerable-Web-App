# Quick Start Guide

## 🚀 Getting Started in 5 Minutes

### Prerequisites
- Docker and Docker Compose installed
- Node.js 20+ (for local development, optional)

### Step 1: Start the Application

```bash
# Start database and web server
docker-compose up -d

# Wait for services to be ready (about 10-15 seconds)
docker-compose ps
```

### Step 2: Verify It's Running

```bash
# Check health endpoint
curl http://localhost:3000/api/health

# Should return: {"status":"ok"}
```

### Step 3: Access the Application

Open your browser: **http://localhost:3000**

### Step 4: Create Your First User

1. Click "Register"
2. Enter email: `test@example.com`
3. Enter password: `test123` (weak password - intentional)
4. Click "Register"

You'll be automatically logged in and redirected to the notes page.

### Step 5: Test Vulnerabilities

#### Test IDOR (Insecure Direct Object Reference)
1. Create a note as User1
2. Note the note ID from the URL or response
3. Register a second user (User2)
4. As User2, access: `http://localhost:3000/api/notes/[note-id]`
5. You can read User1's note! (This is the vulnerability)

#### Test SQL Injection
1. Login and get your token
2. Access: `http://localhost:3000/api/notes/search?q=' OR '1'='1`
3. You'll get all notes regardless of ownership

#### Test Missing Authorization
1. Login as a regular user (not admin)
2. Access: `http://localhost:3000/api/admin/users`
3. You can see all users! (Should require admin role)

#### Test Insecure File Upload
1. Go to `/upload` page
2. Upload any file (even without being logged in)
3. No validation, no restrictions

---

## 📚 Documentation Quick Reference

| Document | Purpose |
|----------|---------|
| `README.md` | Project overview and features |
| `SECURITY_REPORT.md` | **Full security analysis and remediation** |
| `EXECUTIVE_SUMMARY.md` | High-level security findings |
| `VULNERABILITIES.md` | Quick vulnerability reference |
| `TEST_REPORT.md` | Test results and coverage |
| `QUICK_START.md` | This file |

---

## 🧪 Running Tests

```bash
# Run all tests
npm test

# Run tests in watch mode
npm run test:watch

# Run tests with UI
npm run test:ui
```

---

## 🛠️ Useful Commands

```bash
# View logs
docker-compose logs web
docker-compose logs db

# Restart services
docker-compose restart

# Stop services
docker-compose down

# Rebuild and restart
docker-compose down && docker-compose up -d --build

# Create admin user
docker-compose exec web npx tsx scripts/create-admin.ts admin@example.com password123
```

---

## 🔍 Testing Endpoints Manually

Use the provided script:
```bash
./test-endpoints.sh
```

Or use curl:
```bash
# Register
curl -X POST http://localhost:3000/api/auth/register \
  -H "Content-Type: application/json" \
  -d '{"email":"test@example.com","password":"test123"}'

# Login
curl -X POST http://localhost:3000/api/auth/login \
  -H "Content-Type: application/json" \
  -d '{"email":"test@example.com","password":"test123"}'

# Use the token from login response for authenticated requests
```

---

## 📊 What's Included

✅ **10 API Endpoints** - All functional  
✅ **10 Security Vulnerabilities** - All exploitable  
✅ **36 Automated Tests** - All passing  
✅ **Comprehensive Security Report** - Ready for presentation  
✅ **Full Documentation** - Setup to exploitation  

---

## 🎯 Next Steps

1. **Explore the vulnerabilities** using the examples in `SECURITY_REPORT.md`
2. **Read the security report** for detailed analysis
3. **Run the test suite** to verify everything works
4. **Write your security report** using the provided documentation

---

## ❓ Troubleshooting

### Port 5433 already in use?
- Your local PostgreSQL is using port 5432
- The Docker container uses 5433 to avoid conflicts
- This is expected and correct

### Can't connect to database?
- Wait a few seconds after `docker-compose up`
- Check: `docker-compose logs db`
- Database schema is auto-applied on startup

### Build errors?
- Make sure Docker is running
- Try: `docker-compose down && docker-compose build --no-cache`

---

**You're ready to go!** 🎉
