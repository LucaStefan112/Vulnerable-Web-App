# SecureNotes — Intentionally Vulnerable Next.js Application

> ⚠️ **WARNING**  
> This application is intentionally vulnerable and exists only for security research, education, and portfolio demonstration.  
> **DO NOT deploy this application to production or expose it to the public internet.**

---

## 1. Project Overview

SecureNotes is a deliberately vulnerable, full-stack Next.js (App Router) application designed to simulate a realistic SaaS-style web application and demonstrate:

- Real-world application security vulnerabilities
- Offensive exploitation techniques
- Defensive remediation strategies
- Professional security reporting and risk communication

The project follows a complete security lifecycle:

1. Threat modeling
2. Vulnerability implementation
3. Exploitation (PoCs)
4. Risk analysis
5. Secure remediation
6. Retesting

---

## 2. Technology Stack

### Application

- **Next.js 16+** (App Router)
- **TypeScript**
- **Node.js runtime** (not Edge for DB access)

### Backend

- Next.js Route Handlers (`/app/api/*`)
- Server Actions (intentionally misused in some cases)

### Authentication

- Custom JWT-based authentication
- HttpOnly cookies + Authorization header
- Role-based access control (user, admin)

### Database

- **PostgreSQL**
- **Prisma ORM** (v7)

### Infrastructure

- Docker
- Docker Compose
- Environment variables (`.env`)

---

## 3. Application Concept

SecureNotes is a multi-tenant note management platform.

### Core Features

- User registration and login
- CRUD operations on personal notes
- Note sharing (future extension)
- Admin-only dashboard
- File uploads (attachments)
- API-driven backend

The feature set is intentionally chosen to enable natural, realistic security flaws.

---

## 4. High-Level Architecture

```
Browser
  │
  ▼
Next.js App Router
  ├── Middleware (JWT parsing, flawed checks)
  ├── Route Handlers (/api/*)
  ├── Server Actions
  ▼
Prisma ORM
  ▼
PostgreSQL
```

### Trust Boundaries

- Client ↔ Server
- Authenticated ↔ Unauthenticated
- User ↔ Admin
- Server Actions ↔ Route Handlers
- Node runtime ↔ Edge runtime

---

## 5. Authentication & Authorization Model

### Authentication

- JWT tokens signed with a static secret
- Tokens contain:
  - `userId`
  - `email`
  - `role`
- Tokens are long-lived (intentionally insecure)

### Authorization

- Role-based checks are incomplete or missing
- Ownership checks are intentionally flawed
- Some access control is enforced client-side only

---

## 6. API Endpoints

### Auth Endpoints

#### `POST /api/auth/register`

Registers a new user.

**Request Body:**
```json
{
  "email": "user@example.com",
  "password": "password123"
}
```

**Notes:**
- Weak password requirements
- No email verification

#### `POST /api/auth/login`

Authenticates a user and returns a JWT.

**Request Body:**
```json
{
  "email": "user@example.com",
  "password": "password123"
}
```

**Response:**
```json
{
  "token": "<jwt>"
}
```

### Notes Endpoints

#### `GET /api/notes`

Returns all notes belonging to the authenticated user.

#### `GET /api/notes/[id]`

Returns a note by ID.

> ⚠️ **Intentionally vulnerable:**
> - No ownership validation
> - Any authenticated user can access any note ID

#### `POST /api/notes`

Creates a new note.

**Request Body:**
```json
{
  "title": "Test",
  "content": "Secret content"
}
```

#### `DELETE /api/notes/[id]`

Deletes a note by ID.

> ⚠️ **Intentionally vulnerable:**
> - No authorization check

### Admin Endpoints

#### `GET /api/admin/users`

Returns all users.

> ⚠️ **Intentionally vulnerable:**
> - Role check missing or client-side only

### File Upload

#### `POST /api/upload`

Uploads a file.

> ⚠️ **Intentionally vulnerable:**
> - No MIME validation
> - No file extension validation
> - Files stored in a publicly accessible directory

---

## 7. Threat Model (STRIDE)

### Assets

- User credentials
- JWT tokens
- Notes content (confidential data)
- Admin functionality
- Database integrity

### STRIDE Mapping

| Category | Example |
|----------|---------|
| **Spoofing** | Forged or weak JWTs |
| **Tampering** | IDOR via note IDs |
| **Repudiation** | Missing audit logs |
| **Information Disclosure** | Accessing other users' notes |
| **Denial of Service** | Unbounded server actions |
| **Elevation of Privilege** | Admin access without role validation |

---

## 8. Intentional Vulnerabilities (Authoritative List)

This section defines exactly what is expected to be exploited.

### 1. Broken Access Control (IDOR)

- **OWASP:** A01:2021
- **CWE:** CWE-639

**Description:**
- Note IDs are user-controlled
- No ownership verification on read/delete

**Impact:**
- Unauthorized access to other users' notes

---

### 2. Broken Authentication (JWT)

- **OWASP:** A07:2021
- **CWE:** CWE-347

**Description:**
- Weak JWT secret
- Missing algorithm enforcement
- Long token lifetime

**Impact:**
- Token forgery
- Account impersonation

---

### 3. SQL Injection

- **OWASP:** A03:2021
- **CWE:** CWE-89

**Description:**
- Unsafe raw SQL queries
- User input concatenated into queries

**Impact:**
- Database data exposure or modification

---

### 4. Server Action Authorization Bypass

- **OWASP:** A01:2021
- **CWE:** CWE-284

**Description:**
- Server Actions callable without auth checks

**Impact:**
- Privileged operations without authentication

---

### 5. Insecure File Upload

- **OWASP:** A08:2021
- **CWE:** CWE-434

**Description:**
- No file type validation
- Public upload directory

**Impact:**
- Malicious file hosting
- Potential RCE (depending on environment)

---

### 6. Security Misconfiguration

- **OWASP:** A05:2021
- **CWE:** CWE-16

**Description:**
- Missing security headers
- Verbose error messages
- Debug logging enabled

**Impact:**
- Information leakage
- Easier exploitation

---

## 9. Expected Exploitation Goals

An attacker (or security tester) should be able to:

- ✅ Access other users' notes
- ✅ Forge or tamper with JWTs
- ✅ Escalate privileges to admin
- ✅ Extract or manipulate database data
- ✅ Upload malicious files
- ✅ Bypass server-side authorization

---

## 10. Secure Remediation (Later Phase)

Each vulnerability will later be:

1. Fixed using best practices
2. Re-tested using original PoCs
3. Documented in a professional security report

---

## License

See [LICENSE](./LICENSE) file for details.
