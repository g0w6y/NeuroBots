# Frontend Dashboard

**Team:** Aleena Shaji, Mariya Liss

## Problem

API attacks happen in real time, and security teams need to see them happening now, not in a log file tomorrow. Blocks need context: why was this request blocked? What threat does it represent? Is this the same attacker coming back again?

Traditional dashboards show static logs. We need a live, explainable threat intelligence dashboard that shows requests as they happen, color coded by risk, tagged with the exact OWASP API Top 10 category and MITRE ATT&CK technique that triggered the block.

## Solution

Build a React dashboard that pulls live threat data from the gateway admin API and displays it in real time. Show every request, its risk score, whether it was allowed or blocked, and why. Make the data visual so a security operator can scan it at a glance.

## Your Deliverables

You are building the frontend React application with Tailwind CSS and Recharts for charts.

### Part 1: Project Setup (hours 0 to 1)

Create a React app with Vite (faster than Create React App).

```bash
npm create vite@latest neurobots-dashboard -- --template react
cd neurobots-dashboard
npm install
npm install tailwindcss recharts axios
npx tailwindcss init -p
```

Set up Tailwind CSS. Configure tailwind.config.js to extend colors for risk levels:
- green for allowed (low risk)
- yellow for challenged (medium risk)
- red for blocked (high risk)

Structure the project:
- src/components/Dashboard.jsx (main page)
- src/components/ThreatFeed.jsx (live alerts)
- src/components/RiskChart.jsx (score visualization)
- src/components/MitreMatrix.jsx (MITRE techniques)
- src/api/gateway.js (API client)
- src/styles/index.css (Tailwind imports)

### Part 2: API Client (hours 1 to 3)

Create a gateway API client that fetches data from the backend admin endpoints.

Endpoints to call:
- GET /admin/alerts: returns list of blocked and challenged requests
- GET /admin/metrics: returns current metrics (allowed, blocked, challenged counts, latency stats)
- GET /admin/entities: returns list of users with their risk scores and request counts

Create a polling mechanism that fetches new data every 2 seconds.

```javascript
// src/api/gateway.js
const GATEWAY_URL = 'http://127.0.0.1:8081';

export async function getAlerts() {
  const response = await axios.get(`${GATEWAY_URL}/admin/alerts`);
  return response.data;
}

export async function getMetrics() {
  const response = await axios.get(`${GATEWAY_URL}/admin/metrics`);
  return response.data;
}

export async function getEntities() {
  const response = await axios.get(`${GATEWAY_URL}/admin/entities`);
  return response.data;
}
```

Handle CORS by setting appropriate headers on the backend (Access Control Allow Origin).

### Part 3: Live Threat Feed (hours 3 to 9)

Build the main threat feed component that displays every request decision in real time.

Display for each request:
- Decision badge: ALLOWED (green), CHALLENGED (yellow), BLOCKED (red)
- Risk score: 0 to 100 in large bold text
- Method and path: GET /api/accounts/1002
- Subject: who made the request (username or anon:ip)
- IP address: source IP
- Timestamp: when the request was made
- Signals list: the exact signals that fired (jwt_invalid, bola_cross_user, rate_limit, etc.)

Color code by decision:
- Green border and background for allowed
- Yellow for challenged
- Red for blocked

Show signals as small pills with the OWASP and MITRE tags:
- jwt_invalid · API2 · T1078

Sort by most recent first. Show the last 50 requests. Update every 2 seconds with new data.

Use Recharts to show:
- A line chart of allowed vs blocked counts over time (last hour)
- A pie chart of decision breakdown (allowed, challenged, blocked percentages)

### Part 4: Risk Score Gauge (hours 9 to 12)

Add a large risk score gauge at the top showing the current overall system risk (0 to 100).

Color it based on the score:
- 0 to 30: green (safe)
- 31 to 60: yellow (caution)
- 61 to 100: red (danger)

Update this every 2 seconds as new data arrives.

Also show:
- Total requests seen
- Current block rate (% of requests blocked)
- Average latency (from metrics)
- Current detected entities (how many unique users)

### Part 5: MITRE ATT&CK Matrix (hours 12 to 15)

Build a component that shows a grid of MITRE ATT&CK techniques with counts of detections.

Techniques to display (based on our signals):
- T1078 Valid Accounts (bad tokens, weak auth)
- T1119 Automated Collection (enumeration, scraping)
- T1548 Abuse Elevation Control (BFLA)
- T1499 Endpoint Denial of Service (rate abuse)
- T1550 Use Alternate Auth (token replay)
- T1590 Gather Victim Info (reconnaissance)
- T1071 Application Layer (behavioral anomaly)

Show each technique as a box with:
- Technique name
- Count of detections
- Severity color (red for high count)

Update from the metrics endpoint.

### Part 6: Entity Risk Profiles (hours 15 to 18)

Add a section showing per user risk profiles as a table.

Columns:
- Subject (username or anonymous ID)
- Request count
- Risk score (0 to 100, color coded)
- Endpoints accessed
- Objects accessed
- Status (active, blocked, flagged)

Sort by risk score highest first. Allow filtering by name.

Use Recharts to show a mini bar chart of request counts per entity.

### Part 7: Responsive Design (hours 18 to 21)

Make the dashboard work on desktop, tablet and mobile.

Use Tailwind responsive classes:
- Grid layout that stacks on mobile
- Hidden overflow on small screens with horizontal scroll for tables
- Smaller fonts on mobile
- Touch friendly buttons (larger tap targets)

### Part 8: Styling and Polish (hours 21 to 24)

Polish the UI:
- Dark theme (dark background, light text)
- Consistent spacing and alignment
- Smooth transitions for color changes
- Hover effects on rows
- Loading states while fetching data
- Error message display if gateway is unreachable

Use a color palette:
- Dark background: #0f172a
- Cards: #1e293b
- Text: #e2e8f0
- Accent: #3b82f6
- Success: #10b981
- Warning: #f59e0b
- Danger: #ef4444

## Technical Requirements

- React 18 with Vite
- Tailwind CSS for styling
- Recharts for charts (line, pie, bar)
- axios for HTTP requests
- No backend mocking (use real gateway API)
- All data from /admin/ endpoints on the gateway
- Responsive design (mobile, tablet, desktop)
- Polling every 2 seconds for new data

## Data Flow

Gateway /admin/alerts → ThreatFeed component (live updates)
Gateway /admin/metrics → Risk gauge and charts
Gateway /admin/entities → Entity risk table

## Success Criteria

Dashboard must:
1. Display live alerts as requests come in
2. Show risk scores with color coding
3. Display MITRE techniques with counts
4. Show entity risk profiles
5. Update every 2 seconds without manual refresh
6. Be responsive on mobile and desktop
7. Be fast (no lag when displaying 50+ alerts)
8. Look professional and use consistent design

## Environment

- REACT_APP_GATEWAY_URL: http://127.0.0.1:8081 (gateway admin port)
- REACT_APP_POLL_INTERVAL: 2000 (milliseconds)

## Testing

Before 24 hour mark:
1. Start the gateway (npm run dev on backend)
2. Start the dashboard (npm run dev on frontend)
3. Run the attack simulator in another terminal
4. Watch alerts appear live in the dashboard
5. Verify all signals and MITRE tags display correctly
