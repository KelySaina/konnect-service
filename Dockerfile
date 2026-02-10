FROM node:18-alpine

WORKDIR /app

# Copy package files
COPY package*.json ./

# Install dependencies
RUN npm ci --only=production

# Copy application source
COPY . .

# Expose port
EXPOSE 3000

# Create a startup script
RUN echo '#!/bin/sh' > /app/start.sh && \
    echo 'echo "Waiting for database..."' >> /app/start.sh && \
    echo 'sleep 10' >> /app/start.sh && \
    echo 'echo "Running migrations..."' >> /app/start.sh && \
    echo 'node src/database/migrate.js' >> /app/start.sh && \
    echo 'echo "Running seed..."' >> /app/start.sh && \
    echo 'node src/database/seed.js' >> /app/start.sh && \
    echo 'echo "Starting server..."' >> /app/start.sh && \
    echo 'node src/server.js' >> /app/start.sh && \
    chmod +x /app/start.sh

# Start application
CMD ["/app/start.sh"]
