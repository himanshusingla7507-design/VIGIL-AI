# VIGIL frontend

React + Vite frontend for the existing Flask backend.

```powershell
npm install
Copy-Item .env.example .env
npm run dev
```

The API base URL is configured with `VITE_API_BASE_URL` and defaults to
`http://localhost:5000`. Production build and tests:

```powershell
npm run build
npm test
```
