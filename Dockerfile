FROM node:20-alpine

# Run the app from /app/server (your code is in repo/server)
WORKDIR /app/server

# Install deps from /server/package.json
COPY server/package*.json ./
RUN npm install --omit=dev

# Copy server source only
COPY server/. .

# Runtime config
ENV PORT=3333
EXPOSE 3333

# Start the server (this file has the OTP routes)
CMD ["node", "index.js"]
