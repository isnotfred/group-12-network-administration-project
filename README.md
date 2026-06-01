# Group 12 – Network Administration Dashboard

A Flask-based web dashboard for monitoring network devices, viewing logs, managing users, and receiving live camera and device updates.

## Requirements

- Python 3.10 or newer
- PostgreSQL
- `pip`

## Features

- Login and signup with admin approval flow
- Separate admin and user dashboard views
- Real-time device monitoring and log viewing
- Admin user management and role assignment
- WebSocket support for live camera frame viewing
- PostgreSQL-backed storage for users, devices, logs, and IP block records

## Setup

1. **Clone the repository.**

   ```bash
   git clone https://github.com/isnotfred/group-12-network-administration-project.git
   cd group-12-network-administration-project
   ```

2. **Create and activate a virtual environment.**

   ```bash
   python -m venv .venv
   .\.venv\Scripts\Activate.ps1
   ```

3. **Install dependencies.**

   ```bash
   pip install -r requirements.txt
   ```

4. **Create a `.env` file** in the project root and fill in your values. Keep this file private — it contains credentials and secret keys.

   ```env
   SECRET_KEY=replace-with-a-secure-random-value
   ADMIN_USERNAME=admin
   ADMIN_PASSWORD=replace-with-admin-password
   INGEST_KEY=replace-with-camera-or-agent-key
   DATABASE_URL=postgresql://username:password@localhost:5432/network_admin
   ```

5. **Create the PostgreSQL database.** The application creates all required tables automatically on first run.

   ```sql
   CREATE DATABASE network_admin;
   ```

6. **Start the application.**

   ```bash
   python app.py
   ```

7. **Open the app** at `http://localhost:5000`.

## Production

The included `Procfile` runs the app with Gunicorn using a gthread worker class. Use it directly with a Gunicorn-compatible host (e.g., Heroku, Render):

```
web: gunicorn app:app --workers 1 --threads 16 --worker-class gthread --bind 0.0.0.0:$PORT --timeout 120
```

## Network Setup

The network uses a star topology with the router, computer, and camera all connected through a central switch.

| Device   | IP Address     |
| -------- | -------------- |
| Router   | 192.168.1.1    |
| Camera   | 192.168.1.10   |
| Computer | 192.168.1.20   |
| Switch   | —              |

```mermaid
flowchart LR
    Router["Router<br/>192.168.1.1"] --- Switch["Switch"]
    Switch --- Computer["Computer<br/>192.168.1.20"]
    Switch --- Camera["Camera<br/>192.168.1.10"]
```

## Pages & Endpoints

| Path               | Description                        |
| ------------------ | ---------------------------------- |
| `/`                | Home page                          |
| `/login`           | Login                              |
| `/signup`          | Signup (requires admin approval)   |
| `/dashboard`       | User/admin dashboard               |
| `/logs`            | Logs viewer                        |
| `/admin/users`     | Admin user management              |
| `/api/devices`     | Device data API                    |
| `/api/logs`        | Logs API                           |
| `/ingest/devices`  | Device ingest endpoint             |
| `/ingest/status`   | Camera/frame ingest status         |

The camera or ingest agent must include the configured `INGEST_KEY` when sending data to the ingest endpoints.

## Screenshots

### Login Page
![Login Page](screenshots/login-page.png)

### Signup Page
![Signup Page](screenshots/signup-page.png)

### Dashboard (Admin)
![Dashboard Admin](screenshots/dashboard-admin-1.png)
![Dashboard Admin](screenshots/dashboard-admin-2.png)
![Dashboard Admin](screenshots/dashboard-admin-3.png)

### Dashboard (User)
![Dashboard User](screenshots/dashboard-user.png)

### Logs Page
![Logs Page](screenshots/logs-page.png)

### User Management Page
![User Management Page](screenshots/user-management-page.png)

## Contributors

| Name                      | Role                        |
| ------------------------- | --------------------------- |
| Frederick C. Orlain       | Developer                   |
| Mark Joseph D. Cutamora   | Developer                   |
| Franz Marco R. Basbas     | Documentation & other tasks |
| Nikko J. Agcaoili         | Documentation & other tasks |

## License

This project is licensed under the MIT License. See [LICENSE](LICENSE) for details.