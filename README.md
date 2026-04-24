# AtherNex - Red Team vs Blue Team Realtime Demo

AtherNex now runs as two real applications talking over live HTTP traffic:

- Red Team app launches real attack patterns.
- Blue Team app receives that traffic, scores threat risk with AegisAI, and auto-blocks abusive sources.

## Features

- **Two-App Architecture**: Independent Red Team attacker app and Blue Team defense app.
- **Real HTTP Attack Traffic**: Brute force, DDoS-like flood, SQL injection probes, and port scanning.
- **Realtime Detection + Blocking**: Protected target endpoints are monitored and blocked automatically on high-risk behavior.
- **Live Security Telemetry APIs**: Event stream, blocklist, and source overview.
- **Interactive Blue Team Dashboard**: React + GSAP + Recharts UI with real-traffic mode.
- **Model-Based Risk Scoring**: Uses bundled model artifacts (scaler MVP path) to classify request patterns.

## Tech Stack

### Backend
- **Framework**: FastAPI
- **Language**: Python 3.13
- **ML**: scikit-learn (StandardScaler for inference)
- **Port**: 8001 (Blue Team target + defense)

### Red Team App
- **Framework**: FastAPI
- **Language**: Python 3.13
- **HTTP Client**: httpx (async burst traffic)
- **Port**: 8002

### Frontend
- **Framework**: React 18.3
- **Build Tool**: Vite 5.4
- **Charting**: Recharts 2.12
- **Animations**: GSAP 3.15
- **Port**: 5173

## Setup & Installation

### Prerequisites
- Python 3.13+
- Node.js 16+
- npm or yarn

### Backend Setup

```bash
# Create virtual environment
python3.13 -m venv .venv
source .venv/bin/activate

# Install dependencies
pip install -r requirements.txt

# Run the Blue Team backend
python main.py
```

Blue Team backend will start on `http://localhost:8001`

### Red Team App Setup

Use the same Python virtual environment as backend.

```bash
source .venv/bin/activate
python red_team_app.py
```

Red Team app will start on `http://localhost:8002`

### Frontend Setup

```bash
# Install dependencies
npm install

# Start development server
npm run dev
```

The frontend will start on `http://localhost:5173`

### Build for Production

```bash
npm run build
```

## Blue Team API Endpoints

- `GET /health` - Health check endpoint
- `POST /predict` - Get threat prediction for given metrics
- `GET /simulate-attack` - Simulate a staged attack scenario
- `GET /debug/model-info` - Get model artifact information

### Protected target endpoints (receive real attack traffic)

- `POST /target/login`
- `GET /target/ping`
- `GET /target/search?q=...`
- `GET /target/ports/{port}`

### Security telemetry endpoints

- `GET /security/events?limit=120`
- `GET /security/overview`
- `GET /security/blocklist`
- `POST /security/unblock/{source}`
- `POST /security/reset`

## Running All Apps

Terminal 1 (Blue Team backend):
```bash
source .venv/bin/activate
python main.py
```

Terminal 2 (Frontend dashboard):
```bash
npm run dev
```

Terminal 3 (Red Team attacker app):
```bash
source .venv/bin/activate
python red_team_app.py
```

Open these side by side:

- Blue Team dashboard: `http://localhost:5173`
- Red Team launcher: `http://localhost:8002`

## Demo Flow

1. Confirm dashboard is calm in Real Traffic mode.
2. In Red Team app, click `Launch Brute Force`.
3. Blue Team logs and risk chart should spike in real time.
4. Once high risk is detected, source is auto-blocked.
5. Launch attacks again and observe increased `403` responses.

## Project Structure

```
athernex/
├── main.py                 # Blue Team backend + target + defense middleware
├── red_team_app.py         # Red Team attack launcher app
├── requirements.txt        # Python dependencies
├── package.json            # NPM configuration
├── vite.config.js          # Vite configuration
├── index.html              # Vite entry point
├── src/
│   ├── main.jsx            # React entry point
│   └── components/
│       └── CyberMonitoringDashboard.jsx  # Main dashboard component
└── .env.example            # Example environment variables
```

## Notes

- The Red Team app is intentionally restricted to localhost targets for safe demo usage.
- If dependencies are missing in your venv, run `pip install -r requirements.txt`.

## License

MIT
