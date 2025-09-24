FROM node:20-alpine

WORKDIR /app

# Install deps from the root package.json
COPY package*.json ./
RUN npm install --omit=dev

# Copy all source (root)
COPY . .

ENV PORT=3333
EXPOSE 3333

# Start the root index.js
CMD ["node", "index.js"]
