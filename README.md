# AtherNex - Realtime Monitoring Console

A professional cybersecurity anomaly detection system with a real-time monitoring dashboard. The project combines a FastAPI backend with a React frontend featuring animated UI, live threat feeds, and staged attack simulations.

## Features

- **Real-time Threat Detection**: Uses trained anomaly detection models to identify suspicious network patterns
- **Interactive Dashboard**: React-based UI with Recharts for data visualization
- **Live Updates**: Streaming log feed with animated entries
- **Attack Simulation**: Staged attack simulation for demo and testing purposes
- **Dark Theme**: Professional dark-themed interface with GSAP animations
- **Multi-metric Analysis**: Monitors response time, CPU usage, memory, status codes, and retry patterns

## Tech Stack

### Backend
- **Framework**: FastAPI
- **Language**: Python 3.13
- **ML**: scikit-learn (StandardScaler for inference)
- **Port**: 8001

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

# Run the backend
python main.py
```

The backend will start on `http://localhost:8001`

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

## API Endpoints

- `GET /health` - Health check endpoint
- `POST /predict` - Get threat prediction for given metrics
- `GET /simulate-attack` - Simulate a staged attack scenario
- `GET /debug/model-info` - Get model artifact information

## Running Both Services

Terminal 1 (Backend):
```bash
source .venv/bin/activate
python main.py
```

Terminal 2 (Frontend):
```bash
npm run dev
```

Then open `http://localhost:5173` in your browser.

## Project Structure

```
athernex/
├── main.py                 # FastAPI backend
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

## Monitoring Dashboard Features

### Panels
- **Input Panel**: Enter metrics manually or simulate attack
- **Result Panel**: Real-time threat assessment with animated risk meter
- **Logs Panel**: Live feed of all events with timestamps
- **Charts Panel**: Risk score over time and system metrics

### Key Metrics
- Response Time: Network latency (milliseconds)
- Status Code: HTTP response status
- CPU Usage: System processor utilization (%)
- Memory Usage: RAM consumption (%)
- Retry Count: Number of request retries

## License

MIT
