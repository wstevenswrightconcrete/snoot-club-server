FROM node:20-alpine
WORKDIR /app
COPY package*.json ./
RUN npm install --only=prod
COPY . .
ENV PORT=3333
EXPOSE 3333
CMD ["node","index.js"]
