FROM node:20-alpine

RUN apk add --no-cache python3 make g++

WORKDIR /app

COPY package.json package-lock.json* ./
RUN npm ci --omit=dev && npm rebuild bcrypt

COPY src/ ./src/

RUN mkdir -p /app/keys

EXPOSE 3000

CMD ["node", "src/index.js"]
