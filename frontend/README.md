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

The QR Scanner decodes QR images locally with ZXing and requests camera access
only after the user starts a live scan. HTTP(S) destinations are analyzed by
the existing backend URL scanner; other payload types are displayed without
being treated as safe. Destinations never open automatically.
