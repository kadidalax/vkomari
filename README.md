# vKomari

vKomari is a lightweight virtual VPS/node panel. It creates virtual nodes and reports simulated metrics to Komari and CF-VPS-Monitor panels.

## Features

- Manage many virtual nodes from one web UI.
- Report to Komari and CF-VPS-Monitor.
- CF-VPS-Monitor Agent WebSocket policy support: active viewers use realtime reporting, idle panels use background reporting.
- Simulated CPU, memory, swap, disk, network, process, connection, OS, kernel, region, IP, and GPU metadata.
- Import/export nodes and reusable templates.
- Docker Compose deployment.

## Docker Compose

```bash
git clone https://github.com/kadidalax/vkomari.git
cd vkomari
docker compose up -d --build
```

Open:

```text
http://your-server-ip:25770
```

Default login:

```text
username: admin
password: vkomari
```

Change the password after first login.

## Configuration

Optional `.env` file:

```env
PORT=25770
JWT_SECRET=change-this-to-a-long-random-string

# Optional outbound proxy for panels that need it.
# HTTP_PROXY=http://host.docker.internal:10808
# HTTPS_PROXY=http://host.docker.internal:10808
```

Then restart:

```bash
docker compose up -d --build
```

Data is stored in the Docker volume `vkomari_data`.

## Update

```bash
git pull
docker compose up -d --build
```

## Useful Commands

```bash
docker compose logs -f
docker compose restart
docker compose down
```

To remove the app and its stored data:

```bash
docker compose down -v
```

## Local Development

```bash
python -m venv .venv
. .venv/Scripts/activate  # Windows PowerShell: .venv\Scripts\Activate.ps1
pip install -r requirements.txt
uvicorn main:app --host 0.0.0.0 --port 8000 --reload
```

## License

MIT
