FROM node:20-alpine

WORKDIR /app

RUN apk add --no-cache python3 make g++ sqlite

COPY package.json package-lock.json* ./
RUN npm install --omit=dev

COPY src ./src

RUN mkdir -p /app/data /app/data/artifacts

EXPOSE 8080

CMD ["node", "src/server.js"]
