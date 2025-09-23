# Snoot Club Server — Deploy
## Render
- New Web Service → Node
- Build: `npm install` | Start: `node index.js`
- Env: ADMIN_PIN, TWILIO_ACCOUNT_SID, TWILIO_AUTH_TOKEN, TWILIO_FROM
## Docker
```bash
cp .env.example .env
docker compose up --build -d
```
