#!/bin/bash

# Test script for all API endpoints
BASE_URL="http://localhost:3000"

echo "=== Testing All Endpoints ==="
echo ""

# Test 1: Health check
echo "1. Testing GET /api/health"
curl -s "$BASE_URL/api/health" | jq .
echo ""

# Test 2: Register new user
echo "2. Testing POST /api/auth/register"
REGISTER_RESPONSE=$(curl -s -X POST "$BASE_URL/api/auth/register" \
  -H "Content-Type: application/json" \
  -d '{"email":"endpointtest@example.com","password":"test123"}')
echo "$REGISTER_RESPONSE" | jq .
TOKEN=$(echo "$REGISTER_RESPONSE" | jq -r '.token // empty')
echo ""

# Test 3: Login
echo "3. Testing POST /api/auth/login"
LOGIN_RESPONSE=$(curl -s -X POST "$BASE_URL/api/auth/login" \
  -H "Content-Type: application/json" \
  -d '{"email":"endpointtest@example.com","password":"test123"}')
echo "$LOGIN_RESPONSE" | jq .
TOKEN=$(echo "$LOGIN_RESPONSE" | jq -r '.token // empty')
echo "Token: ${TOKEN:0:50}..."
echo ""

# Test 4: Create note
echo "4. Testing POST /api/notes"
NOTE_RESPONSE=$(curl -s -X POST "$BASE_URL/api/notes" \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer $TOKEN" \
  -d '{"title":"Endpoint Test Note","content":"Testing all endpoints"}')
echo "$NOTE_RESPONSE" | jq .
NOTE_ID=$(echo "$NOTE_RESPONSE" | jq -r '.id // empty')
echo ""

# Test 5: Get all notes
echo "5. Testing GET /api/notes"
curl -s "$BASE_URL/api/notes" \
  -H "Authorization: Bearer $TOKEN" | jq .
echo ""

# Test 6: Get specific note
echo "6. Testing GET /api/notes/$NOTE_ID"
curl -s "$BASE_URL/api/notes/$NOTE_ID" \
  -H "Authorization: Bearer $TOKEN" | jq .
echo ""

# Test 7: Search notes
echo "7. Testing GET /api/notes/search?q=test"
curl -s "$BASE_URL/api/notes/search?q=test" \
  -H "Authorization: Bearer $TOKEN" | jq .
echo ""

# Test 8: Admin users (should work even without admin role - intentional vulnerability)
echo "8. Testing GET /api/admin/users"
curl -s "$BASE_URL/api/admin/users" \
  -H "Authorization: Bearer $TOKEN" | jq .
echo ""

# Test 9: File upload
echo "9. Testing POST /api/upload"
echo "test upload content" > /tmp/upload-test.txt
UPLOAD_RESPONSE=$(curl -s -X POST "$BASE_URL/api/upload" \
  -H "Authorization: Bearer $TOKEN" \
  -F "file=@/tmp/upload-test.txt")
echo "$UPLOAD_RESPONSE" | jq .
rm /tmp/upload-test.txt
echo ""

# Test 10: Delete note
echo "10. Testing DELETE /api/notes/$NOTE_ID"
curl -s -X DELETE "$BASE_URL/api/notes/$NOTE_ID" \
  -H "Authorization: Bearer $TOKEN" | jq .
echo ""

# Test 11: Error cases
echo "11. Testing error cases"
echo "11a. Register with existing email:"
curl -s -X POST "$BASE_URL/api/auth/register" \
  -H "Content-Type: application/json" \
  -d '{"email":"endpointtest@example.com","password":"test123"}' | jq .
echo ""

echo "11b. Login with wrong password:"
curl -s -X POST "$BASE_URL/api/auth/login" \
  -H "Content-Type: application/json" \
  -d '{"email":"endpointtest@example.com","password":"wrong"}' | jq .
echo ""

echo "11c. Access notes without token:"
curl -s "$BASE_URL/api/notes" | jq .
echo ""

echo "11d. Access non-existent note:"
curl -s "$BASE_URL/api/notes/99999" \
  -H "Authorization: Bearer $TOKEN" | jq .
echo ""

echo "=== All endpoint tests completed ==="
