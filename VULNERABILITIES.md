# Complete List of Vulnerabilities in SecureNotes

This document provides a comprehensive list of all intentional security vulnerabilities implemented in the SecureNotes application.

## 🔴 Critical Vulnerabilities

### 1. Broken Access Control (IDOR) - OWASP A01:2021
**CWE:** CWE-639  
**Severity:** High  
**Location:** `app/api/notes/[id]/route.ts`

**Description:**
- Note IDs are user-controlled via URL parameters
- No ownership verification on GET and DELETE operations
- Any authenticated user can access or delete any note by ID

**Affected Endpoints:**
- `GET /api/notes/[id]` - Line 42: No ownership check
- `DELETE /api/notes/[id]` - Line 112: No ownership check before delete

**Exploitation:**
```bash
# User1 creates note with ID 5
# User2 can access it:
GET /api/notes/5
Authorization: Bearer <user2_token>

# User2 can delete it:
DELETE /api/notes/5
Authorization: Bearer <user2_token>
```

**Impact:**
- Unauthorized access to other users' private notes
- Unauthorized deletion of other users' notes
- Data breach and privacy violation

---

### 2. SQL Injection - OWASP A03:2021
**CWE:** CWE-89  
**Severity:** Critical  
**Location:** `app/api/notes/search/route.ts`

**Description:**
- Unsafe raw SQL query using `$queryRawUnsafe`
- User input directly concatenated into SQL query
- No parameterization or sanitization

**Affected Endpoint:**
- `GET /api/notes/search?q=...` - Line 38: Direct string interpolation

**Exploitation:**
```bash
# Extract all notes:
GET /api/notes/search?q=' OR '1'='1

# Potential data manipulation:
GET /api/notes/search?q='; UPDATE "User" SET role='admin' WHERE email='attacker@example.com'; --
```

**Impact:**
- Database data exposure
- Potential data modification
- Database structure disclosure via error messages
- Possible privilege escalation

---

### 3. Missing Authorization - OWASP A01:2021
**CWE:** CWE-284  
**Severity:** High  
**Location:** `app/api/admin/users/route.ts`, `middleware.ts`

**Description:**
- Admin endpoint accessible to all authenticated users
- No role-based access control (RBAC) check
- Regular users can access sensitive admin functionality

**Affected Endpoints:**
- `GET /api/admin/users` - Line 29: Role check missing
- `app/admin/page.tsx` - Line 37: Client-side check only

**Exploitation:**
```bash
# Regular user accessing admin endpoint:
GET /api/admin/users
Authorization: Bearer <regular_user_token>

# Returns all users with sensitive information
```

**Impact:**
- Unauthorized access to sensitive user data
- Privacy violation
- Potential for further attacks (email enumeration, etc.)

---

### 4. Insecure File Upload - OWASP A08:2021
**CWE:** CWE-434  
**Severity:** High  
**Location:** `app/api/upload/route.ts`

**Description:**
- No authentication required (works without token)
- No MIME type validation
- No file extension validation
- No file size limits
- Files stored in publicly accessible directory
- Path traversal possible via filename

**Affected Endpoint:**
- `POST /api/upload` - Multiple vulnerabilities

**Exploitation:**
```bash
# Upload without authentication:
POST /api/upload
Content-Type: multipart/form-data
file: malicious.exe

# Path traversal:
POST /api/upload
file: ../../../etc/passwd

# Upload executable:
POST /api/upload
file: shell.php
```

**Impact:**
- Malicious file hosting
- Path traversal attacks
- Potential Remote Code Execution (RCE)
- Server compromise
- Denial of Service (large files)

---

### 5. Broken Authentication (JWT) - OWASP A07:2021
**CWE:** CWE-347  
**Severity:** High  
**Location:** `lib/auth.ts`

**Description:**
- Weak static JWT secret (defaults to 'weak-secret-key-12345')
- No algorithm enforcement (allows algorithm confusion attacks)
- Long token expiry (365 days)
- Tokens stored in localStorage (not HttpOnly cookies)
- No algorithm verification in token verification

**Affected Code:**
- `lib/auth.ts` - Lines 5, 17-20, 24-28

**Exploitation:**
```bash
# 1. Decode token (no signature verification needed with weak secret)
# 2. Modify payload (change role to 'admin')
# 3. Sign with weak secret or use 'none' algorithm
# 4. Use forged token to access admin endpoints
```

**Impact:**
- Token forgery
- Account impersonation
- Privilege escalation
- Session hijacking

---

### 6. Server Action Authorization Bypass - OWASP A01:2021
**CWE:** CWE-284  
**Severity:** Medium  
**Location:** `app/actions/notes.ts`

**Description:**
- Server Actions callable without proper authorization checks
- `deleteNote()` has no ownership validation
- `getAllUsers()` has no role check

**Affected Functions:**
- `deleteNote()` - Line 46: No ownership check
- `getAllUsers()` - Line 67: No role check

**Impact:**
- Unauthorized operations via Server Actions
- Bypass of API route protections

---

## 🟡 Security Misconfigurations

### 7. Security Misconfiguration - OWASP A05:2021
**CWE:** CWE-16  
**Severity:** Medium  
**Location:** Multiple files

**Description:**
- Missing security headers (CSP, X-Frame-Options, etc.)
- Verbose error messages exposing system details
- Debug logging enabled in production
- Cookies not HttpOnly or Secure
- Tokens returned in response body

**Affected Areas:**
- All API routes: Verbose error messages
- `app/api/auth/register/route.ts`: Tokens in response body
- `app/api/auth/login/route.ts`: Tokens in response body
- Cookies: `httpOnly: false`, `secure: false`

**Impact:**
- Information leakage
- Easier exploitation
- XSS attacks possible
- Session hijacking

---

### 8. Weak Password Requirements
**Severity:** Low-Medium  
**Location:** `app/api/auth/register/route.ts`

**Description:**
- No password strength requirements
- No minimum length enforcement
- No complexity requirements
- No rate limiting on registration

**Impact:**
- Weak passwords easily cracked
- Account takeover via brute force
- Credential stuffing attacks

---

### 9. No Rate Limiting
**Severity:** Medium  
**Location:** Multiple endpoints

**Description:**
- No rate limiting on authentication endpoints
- No rate limiting on registration
- No rate limiting on file uploads
- No rate limiting on API endpoints

**Affected Endpoints:**
- `POST /api/auth/login`
- `POST /api/auth/register`
- `POST /api/upload`
- All other endpoints

**Impact:**
- Brute force attacks
- Denial of Service (DoS)
- Resource exhaustion

---

### 10. Verbose Error Messages
**Severity:** Low-Medium  
**Location:** Multiple files

**Description:**
- Error messages reveal system information
- Database errors expose structure
- Stack traces in error responses

**Examples:**
- `app/api/notes/search/route.ts` - Line 53: Error details exposed
- `app/api/notes/[id]/route.ts` - Line 123: Verbose error messages

**Impact:**
- Information disclosure
- Easier exploitation
- System fingerprinting

---

## 📍 Vulnerability Locations Summary

### API Routes
1. **`app/api/notes/[id]/route.ts`**
   - IDOR in GET endpoint (line 42)
   - IDOR in DELETE endpoint (line 112)
   - Verbose error messages (line 123)

2. **`app/api/notes/search/route.ts`**
   - SQL Injection (line 38)
   - Verbose error messages (line 47-53)

3. **`app/api/admin/users/route.ts`**
   - Missing authorization (line 29)

4. **`app/api/upload/route.ts`**
   - No authentication (line 7)
   - No file validation (lines 19-22)
   - Path traversal risk (line 33)
   - Public directory (line 34)

5. **`app/api/auth/register/route.ts`**
   - Weak password requirements (line 20)
   - No email verification (line 20)
   - Tokens in response body (line 59)
   - Insecure cookies (lines 63-64)

6. **`app/api/auth/login/route.ts`**
   - No rate limiting (line 6)
   - Verbose error messages (line 24)
   - Insecure cookies (lines 60-61)

### Core Libraries
7. **`lib/auth.ts`**
   - Weak JWT secret (line 5)
   - No algorithm enforcement (lines 17-20, 24-28)
   - Long token expiry (line 18)
   - Insecure cookie handling (line 39)

### Server Actions
8. **`app/actions/notes.ts`**
   - Authorization bypass (line 7)
   - No ownership check in deleteNote (line 46)
   - No role check in getAllUsers (line 67)

### Middleware
9. **`middleware.ts`**
   - Flawed JWT checks (line 5)
   - Incomplete authorization (line 43)
   - Admin routes not protected (line 44)

### Frontend
10. **`app/admin/page.tsx`**
    - Client-side role check only (line 37)

11. **`app/notes/[id]/page.tsx`**
    - IDOR vulnerability (line 38)

12. **`app/login/page.tsx` & `app/register/page.tsx`**
    - Tokens stored in localStorage (insecure)

---

## 🎯 Exploitation Examples

### IDOR Attack
```bash
# User1 creates note (ID: 1)
# User2 accesses it:
curl -H "Authorization: Bearer <user2_token>" \
  http://localhost:3000/api/notes/1

# User2 deletes it:
curl -X DELETE \
  -H "Authorization: Bearer <user2_token>" \
  http://localhost:3000/api/notes/1
```

### SQL Injection Attack
```bash
# Extract all notes:
curl -H "Authorization: Bearer <token>" \
  "http://localhost:3000/api/notes/search?q=' OR '1'='1"
```

### Privilege Escalation
```bash
# 1. Login as regular user
# 2. Access admin endpoint:
curl -H "Authorization: Bearer <regular_user_token>" \
  http://localhost:3000/api/admin/users

# 3. Or forge JWT with admin role
```

### File Upload Attack
```bash
# Upload without auth:
curl -X POST \
  -F "file=@malicious.php" \
  http://localhost:3000/api/upload

# Path traversal:
curl -X POST \
  -F "file=@test.txt;filename=../../../etc/passwd" \
  http://localhost:3000/api/upload
```

---

## 📊 Vulnerability Statistics

- **Total Vulnerabilities:** 10 major categories
- **Critical:** 5
- **High:** 3
- **Medium:** 2
- **OWASP Top 10 Coverage:** 6 categories
- **CWE Coverage:** 8 unique CWEs

---

## ✅ Verification

All vulnerabilities are:
- ✅ Documented in code with comments
- ✅ Verified by automated tests (36 tests)
- ✅ Exploitable and reproducible
- ✅ Ready for security report documentation

---

## 🔒 Security Report Ready

This application is intentionally vulnerable and ready for:
- Penetration testing
- Security report writing
- Vulnerability demonstration
- Security training exercises
- Portfolio demonstration

**⚠️ DO NOT deploy to production or expose to the public internet.**
