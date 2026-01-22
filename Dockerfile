FROM node:20-alpine

WORKDIR /app

# Copy package files
COPY package*.json ./
COPY prisma.config.ts ./
COPY prisma/schema.prisma ./prisma/

# Install dependencies
RUN npm install

# Generate Prisma client
RUN npx prisma generate

# Copy the rest of the application
COPY . .

# Copy and set up entrypoint script
COPY docker-entrypoint.sh /usr/local/bin/
RUN chmod +x /usr/local/bin/docker-entrypoint.sh

# Build the application
RUN npm run build

EXPOSE 3000

ENTRYPOINT ["docker-entrypoint.sh"]
CMD ["npm", "start"]
