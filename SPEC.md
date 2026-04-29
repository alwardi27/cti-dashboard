# CTI Dashboard Specification

## Project Overview
- **Project name**: CTI Dashboard
- **Type**: Single-page web application (HTML/CSS/JS)
- **Core functionality**: Display latest vulnerabilities and CVEs from public threat intel sources (NVD API)
- **Target users**: Security analysts, SOC teams, threat researchers

## Visual Specification

### Layout
- Dark theme with cybersecurity aesthetic (terminal/hacker vibe)
- Header with dashboard title and last refresh timestamp
- Stats cards row showing key metrics
- Two-column grid: CVE list (left), Vulnerability details (right)
- Fixed refresh indicator and controls

### Color Palette
- Background: `#0a0e17` (deep navy black)
- Surface: `#111827` (dark slate)
- Primary accent: `#00ff9d` (neon green - terminal style)
- Secondary accent: `#0ea5e9` (cyber blue)
- Alert colors: `#ef4444` (critical), `#f59e0b` (high), `#22c55e` (medium/low)
- Text: `#e2e8f0` (light gray), `#94a3b8` (muted)

### Typography
- Headings: JetBrains Mono (monospace)
- Body: Inter
- Code/IDs: Fira Code

### Components
1. **Stats Cards** - 4 cards showing: Total CVEs, Critical, High, Recent 24h
2. **CVE List** - Scrollable table with filters (severity, date)
3. **CVE Detail Panel** - Expanded view with description, CVSS, references
4. **Search Bar** - Filter CVEs by keyword
5. **Refresh Controls** - Auto-refresh toggle, manual refresh button

## Functionality Specification

### Data Source
- NVD (National Vulnerability Database) API v2
- Endpoint: `https://services.nvd.nist.gov/rest/json/cves/2.0`
- Fetch latest vulnerabilities with configurable results per page

### Features
1. **Auto-refresh**: Fetch new data every 5 minutes (toggleable)
2. **Severity Filtering**: Filter by CVSS score (Critical ≥9, High ≥7, Medium ≥4)
3. **Search**: Filter by CVE ID, description keyword
4. **CVE Details**: Click to expand and view full details
5. **External Links**: Direct links to NVD for each CVE
6. **Loading States**: Skeleton loaders during data fetch
7. **Error Handling**: Graceful error messages if API fails

### Interactions
- Click CVE row → expand detail panel with smooth animation
- Hover rows → subtle highlight
- Filter buttons → instant client-side filtering
- Search input → debounced filtering (300ms)

## Technical Implementation

### Architecture
- Vanilla HTML/CSS/JavaScript (no build step)
- Fetch API for HTTP requests
- CSS Grid and Flexbox for layout
- CSS custom properties for theming

### Performance
- Virtual scrolling not needed (limit to 50 results)
- Debounced search input
- Cache last fetch in memory

## Acceptance Criteria
1. Dashboard loads and displays CVE data from NVD API
2. Stats cards accurately reflect loaded data counts
3. Severity filters work correctly
4. Search filters CVE list by text match
5. Clicking a CVE shows detailed information
6. Auto-refresh toggles work and update data
7. Error state displays if API call fails
8. All external resource URLs are valid and accessible