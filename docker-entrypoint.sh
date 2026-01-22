#!/bin/sh
set -e

echo "Waiting for database to be ready..."

# Wait for database to be accessible and apply schema
max_attempts=30
attempt=0
success=0

while [ $attempt -lt $max_attempts ] && [ $success -eq 0 ]; do
  if npx prisma db push --accept-data-loss; then
    echo "Database schema applied successfully!"
    success=1
  else
    attempt=$((attempt + 1))
    if [ $attempt -lt $max_attempts ]; then
      echo "Database is unavailable or schema push failed - attempt $attempt/$max_attempts - sleeping"
      sleep 2
    fi
  fi
done

if [ $success -eq 0 ]; then
  echo "Failed to apply database schema after $max_attempts attempts"
  exit 1
fi

# Create uploads directory if it doesn't exist
mkdir -p /app/public/uploads
chmod 755 /app/public/uploads
echo "Uploads directory ready"

exec "$@"
