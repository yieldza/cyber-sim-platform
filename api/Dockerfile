FROM node:20-alpine

WORKDIR /app

RUN apk add --no-cache python3 make g++ sqlite

# Build context is the project root so agent/ is reachable.
COPY api/package.json api/package-lock.json* ./
RUN npm install --omit=dev

COPY api/src ./src
# Bundle the agent/ directory so /api/agents/download/:lang can serve them.
COPY agent ./agent

RUN mkdir -p /app/data /app/data/artifacts

EXPOSE 8080

CMD ["node", "src/server.js"]
