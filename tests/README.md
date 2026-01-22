# Test Suite Documentation

## Overview

This test suite verifies all API endpoints and intentionally tests security vulnerabilities to ensure they are present and exploitable.

## Test Structure

```
tests/
├── setup.ts                    # Test environment setup
├── api/
│   ├── health.test.ts         # Health endpoint tests
│   ├── auth.test.ts           # Authentication tests
│   ├── notes.test.ts          # Notes CRUD + IDOR vulnerability tests
│   ├── admin.test.ts          # Admin endpoint + missing auth tests
│   ├── vulnerabilities.test.ts # All security vulnerability tests
│   └── edge-cases.test.ts     # Edge cases and error handling
└── README.md                   # This file
```

## Running Tests

### Run all tests
```bash
npm test
```

### Run tests in watch mode
```bash
npm run test:watch
```

### Run tests with UI
```bash
npm run test:ui
```

### Run specific test file
```bash
npx vitest run tests/api/auth.test.ts
```

## Test Coverage

### ✅ Health Endpoint
- Returns status ok

### ✅ Authentication
- User registration (success and error cases)
- User login (success and error cases)
- Duplicate email handling
- Missing field validation

### ✅ Notes CRUD
- Create notes
- List user's notes
- Get note by ID
- Delete notes
- Authentication required

### ✅ Security Vulnerabilities (Intentional)

#### IDOR (Insecure Direct Object Reference)
- ✅ User can access other users' notes
- ✅ User can delete other users' notes

#### SQL Injection
- ✅ Search endpoint vulnerable to SQL injection
- ✅ Can extract all notes with `' OR '1'='1`

#### Missing Authorization
- ✅ Regular users can access admin endpoint
- ✅ No role-based access control

#### Insecure File Upload
- ✅ Files can be uploaded without authentication
- ✅ No file type validation
- ✅ No file size limits
- ✅ Path traversal possible

#### Weak JWT
- ✅ Weak secret key
- ✅ Long token expiry (365 days)

### ✅ Edge Cases
- Invalid JSON handling
- Empty request bodies
- Very long inputs
- Invalid tokens
- Malformed headers
- Non-numeric IDs
- Path traversal attempts
- Large file uploads

## Test Results

All tests should pass, confirming:
1. All endpoints work correctly
2. All intentional vulnerabilities are present
3. Error handling works as expected
4. Edge cases are handled (or expose vulnerabilities)

## Notes

- Tests run against `http://localhost:3000` by default
- Set `TEST_BASE_URL` environment variable to test against different URLs
- Tests create test users with unique emails (timestamp-based)
- Some tests verify vulnerabilities exist (this is intentional)

## Continuous Integration

These tests can be integrated into CI/CD pipelines to ensure:
- All endpoints remain functional
- Vulnerabilities are not accidentally fixed
- New code doesn't break existing functionality
