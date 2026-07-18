# BruteForge — Engineering Report

## Overview

BruteForge is a modular brute-force testing framework designed for authorized security assessments. Built over three weeks as an internal tool, it replaces a collection of one-off scripts with a unified plugin architecture.

## Architecture

### Plugin System

The `BasePlugin` abstract class defines the contract:

```python
class BasePlugin(ABC):
    name: str
    description: str
    default_port: int
    
    @abstractmethod
    def authenticate(self, host, port, username, password, timeout) -> dict
    @abstractmethod
    def detect(self, host, port, timeout) -> bool
```

Each plugin lives in `plugins/` and self-registers via a metaclass registry. The `PluginLoader` scans `plugins/` directory at startup.

### Engine (`BruteForgeEngine`)

The engine coordinates:
1. **WordlistManager** — reads and yields passwords line-by-line (generator, not bulk load)
2. **ThrottleManager** — enforces delay between attempts, tracks per-target rate limits
3. **ProgressManager** — wraps tqdm for real-time progress bar per target

### Threading Model

`concurrent.futures.ThreadPoolExecutor` with configurable max workers. Each worker pulls from a queue of (username, password) tuples and calls `plugin.authenticate()`. Found credentials are published to an `asyncio.Queue` for real-time output.

## Plugin Implementations

### SSH Plugin
- Uses paramiko.SSHClient with AutoAddPolicy
- Handles: AuthenticationException, SSHException, socket.timeout
- Detects service by banner grab on port 22

### FTP Plugin
- Uses ftplib.FTP
- Handles: error_perm, error_temp, socket.timeout
- Detects by connecting and checking 220 banner

### SMTP Plugin
- Uses smtplib.SMTP with ehlo() / starttls()
- Tests AUTH LOGIN and AUTH PLAIN
- Detects by EHLO response containing AUTH

### HTTP Basic Plugin
- Sends GET with Authorization header
- Checks for 200 vs 401/403 response
- Supports HTTPS with verify=False

### Web Form Plugin
- POST to login endpoint with form data
- Configurable success/failure indicators
- Session cookie tracking

## Performance

- Single thread: ~50 auth attempts/second (SSH, LAN)
- 8 threads: ~350 attempts/second (limited by handshake overhead)
- FTP and HTTP significantly faster (~1000/sec with threading)

## Limitations

1. No distributed brute-forcing (yet)
2. SMTP plugin fails on Exim with certain AUTH configurations
3. Wordlist loaded entirely into RAM — memory-bounded
4. No CAPTCHA handling (intentional — that's not the point)

## Testing

100 unit tests covering:
- Plugin registry and loading
- Each plugin's authenticate() with mocked sockets
- Wordlist manager edge cases (empty lines, comments, missing files)
- ThrottleManager timing accuracy
- Engine dispatch logic
- Progress bar integration
- Error handling for all network exceptions

## Future Work

- Plugin SDK documentation for third-party modules
- Distributed worker coordination via Redis
- Kerberos plugin
- Database credential testing (MySQL, PostgreSQL)
