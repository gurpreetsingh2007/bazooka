# Bazooka

Bazooka is a lightweight host process manager served from one Docker container and one port. The Go backend reads Linux process and host data from `/proc` through gopsutil; Go was chosen because it produces a small, single static binary with direct process signaling and low idle overhead.

## Features

- Host PID, parent PID, name, user, CPU percentage, resident memory, threads, state and command line.
- Two second refresh with pause, sortable columns, field based search and parent/child tree view. Search supports `pid:`, `ppid:`, `port:`, `service:`, `source:system`, `source:docker`, `location:`, `exe:`, `cwd:`, `name:`, `user:`, `cmd:` and `state:`; combine terms with spaces and quote phrases such as `cmd:"python -m yubal_api"`.
- Source tags classify each process as **System**, **Docker**, **Container**, or **Host**, using its Linux cgroup. Bazooka's own PID is omitted from the managed-process list so it cannot be mistaken for a host workload.
- Process details show executable path, working directory, service/cgroup name, and local and remote TCP/UDP socket ports. Select a row to open the action and details panel.
- Socket discovery follows host PID file descriptors into each process's network namespace, so it can show host service ports even though Bazooka keeps its own container networking.
- Host data is collected every two seconds while an authenticated dashboard is active. Collection stops after eight seconds without dashboard requests and resumes on the next request, keeping idle overhead low.
- CPU and memory cards read host-wide `/proc` metrics. CPU uses interval deltas smoothed across refreshes; memory used is total RAM minus `MemAvailable`.
- Linux `sleep` is shown as **Sleeping**; this normally means the process is waiting for work and does not indicate a stopped service.
- End (SIGTERM), force kill (SIGKILL), pause (SIGSTOP) and resume (SIGCONT), with confirmation and optional descendants.
- PID 1 and Bazooka's own PID are protected from signals.
- Host CPU, memory, load average, uptime and process count.
- Required `TM_TOKEN`, constant time token checks, HTTP only login cookie, and per-client login throttling.

## Run with Docker Compose

```sh
cp .env.example .env
# Replace the example token with a unique secret:
openssl rand -hex 32
# Put the generated value in .env as TM_TOKEN=...
docker compose up -d --build
```

Open `http://localhost:8080` and enter the same `TM_TOKEN`. The HTTP-only browser session lasts seven days and is restored after a page reload. Set `PORT` in `.env` to change the listening and published port (the default is 8080). Do not commit `.env`.

## Coolify

1. Create a **Docker Compose** resource from this Git repository.
2. Set `TM_TOKEN` to a long random secret in the resource's environment variables. Optionally set `PORT` (default `8080`).
3. Configure the domain and HTTPS on Coolify's reverse proxy, forwarding to the container port selected by `PORT`.
4. Deploy. Keep the compose `pid: host` setting; it is required for host process visibility. The application itself serves plain HTTP and does not redirect to HTTPS.

## Verify host processes

After login, check for host PIDs such as the host's `systemd` (usually PID 1), `sshd`, or other services that do not belong to the Bazooka container. Bazooka refuses to signal PID 1. If the table contains only container processes, confirm that Docker Compose has `pid: host`, the container was recreated after that setting was applied, and the Docker host is Linux. Host PID namespaces and `/proc` visibility are Linux host features; Docker Desktop on macOS or Windows cannot expose the underlying desktop OS process table this way.

The Compose file drops all capabilities, then adds only `KILL` and `SYS_PTRACE`; it runs as root to inspect and signal host-owned processes, uses a read-only root filesystem, enables `no-new-privileges`, and provides a small `/tmp` tmpfs. Process access is limited by the Docker host's kernel and security policy.

## Development

```sh
npm install
npm run dev
```

The Vite dev server serves the frontend only; run the backend separately with `TM_TOKEN=dev-secret PORT=8080 go run ./backend`, then proxy `/api` to `http://localhost:8080` for local interactive development. The production Docker image serves both frontend and API from port 8080.
