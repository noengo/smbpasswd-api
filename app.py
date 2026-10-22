#!/usr/bin/env python3
"""smbpasswd-web is a simple web interface to smbpasswd.

The only purpose is to allow a user to change its samba password using a webbrowser,
no user adding, no machine account, nothing, plain simple changing a password.

Requires Python >= 3.8, tested on 3.13 / 3.14. Unix only (uses fcntl).
"""

import argparse
import contextlib
import fcntl
import functools
import hashlib
import hmac
import http.server
import json
import math
import os
import pwd
import re
import secrets
import socket
import ssl
import stat
import subprocess
import sys
import tempfile
import threading
import time
import traceback
import unicodedata
from http import HTTPStatus
from pathlib import Path

__author__ = "Tercio Gaudencio FIlho"
__copyright__ = "Copyright 2019, Tercio Gaudencio Filho"
__credits__ = ["Tercio Gaudencio Filho"]
__license__ = "MIT"
__version__ = "1.2.0"
__maintainer__ = "Tercio Gaudencio FIlho"
__email__ = "terciofilho [at] gmail.com"
__status__ = "Production"

_DEFAULT_HTTP_PORT = 8080
_DEFAULT_HTTPS_PORT = 8443

_DEFAULT_ADDRESS = "localhost"

_DEFAULT_SSL_CERT = "res/fullchain.pem"
_DEFAULT_SSL_KEY = "res/privkey.pem"

# All paths are resolved from the application folder, so the script behaves the
# same whatever the current working directory is (e.g. when started by systemd).
_APP_PATH = Path(__file__).resolve().parent
_RES_PATH = _APP_PATH / "res"
_STATIC_PATH = _APP_PATH / "static"
_TOKENS_FILE = _RES_PATH / "tokens"
_LOCK_FILE = _RES_PATH / ".tokens.lock"

# Maximum accepted size of an API request body (bytes)
_MAX_BODY_SIZE = 64 * 1024

# Socket timeout (seconds) for a client connection: TLS handshake, request, body
_REQUEST_TIMEOUT = 15

# Maximum number of connections handled at the same time, in total and per
# client IP. The per-IP limit is what stops one client from holding all the
# slots (behind a reverse proxy every request has the proxy's IP: enforce the
# per-client limit there instead, or raise --max-conn-per-ip).
_DEFAULT_MAX_CONNECTIONS = 256
_DEFAULT_MAX_CONNECTIONS_PER_IP = 8

# Default validity of a token (hours) and accepted range for --token-ttl
_DEFAULT_TOKEN_TTL_HOURS = 24
_MAX_TOKEN_TTL_HOURS = 24 * 365

_MAX_PASSWORD_LENGTH = 256

# sAMAccountName-like user names; the first character can't be "-" so the name
# can never be read as a command line option by smbpasswd/samba-tool.
_USERNAME_RE = re.compile(r"[A-Za-z0-9_][A-Za-z0-9._-]{0,63}")
_TOKEN_RE = re.compile(r"[0-9a-f]{64}")

# Sent with every response (see SmbpasswdRequestHandler.end_headers)
_SECURITY_HEADERS = (
    ("Content-Security-Policy",
     "default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self' data:; "
     "font-src 'self'; connect-src 'self'; base-uri 'none'; form-action 'none'; "
     "frame-ancestors 'none'"),
    ("X-Content-Type-Options", "nosniff"),
    ("X-Frame-Options", "DENY"),
    ("Referrer-Policy", "no-referrer"),
    ("Cache-Control", "no-store"),
    ("Cross-Origin-Opener-Policy", "same-origin"),
    ("Permissions-Policy", "camera=(), microphone=(), geolocation=()"),
)

_use_sudo = False
_use_samba_tool = False
_verbose = False
_token_ttl = _DEFAULT_TOKEN_TTL_HOURS * 3600
# Strict-Transport-Security max-age in seconds; 0 = header not sent. HSTS applies
# to the whole host name (every port), so it is opt-in (--hsts-max-age).
_hsts_max_age = 0

# In-process lock (request threads); _locked_tokens() adds an flock() so the
# "gen-token" command and the running server never write the file at the same time.
_tokens_lock = threading.Lock()


def _resolve_path(path):
    """Resolve a user-supplied path relative to the app folder if it is not absolute."""
    path = Path(path)
    return path if path.is_absolute() else _APP_PATH / path


def _is_valid_username(username):
    return isinstance(username, str) and _USERNAME_RE.fullmatch(username) is not None


def _is_valid_password(password):
    """Server-side check: the API can be called without the web page."""
    if not isinstance(password, str) or not 0 < len(password) <= _MAX_PASSWORD_LENGTH:
        return False
    # No control characters (newline would break the stdin protocol, NUL the
    # command) and no lone surrogates (not encodable in UTF-8).
    return not any(unicodedata.category(char) in ("Cc", "Cs") for char in password)


def _hash_token(token):
    return hashlib.sha256(token.encode("ascii")).hexdigest()


# ---------------------------------------------------------------------------
# Token storage: res/tokens, one "username<TAB>sha256(token)<TAB>created" per line
# ---------------------------------------------------------------------------

def _chown_to_res_owner(fd):
    """When running as root (e.g. an admin running gen-token), keep the files owned
    by the owner of the res folder, so the server user can still read them."""
    if os.geteuid() == 0:
        res_stat = _RES_PATH.stat()
        os.fchown(fd, res_stat.st_uid, res_stat.st_gid)


def _prepare_storage():
    """Create the res folder and make sure it and the tokens file are private."""
    _RES_PATH.mkdir(mode=0o700, exist_ok=True)
    for path, mode in ((_RES_PATH, 0o700), (_TOKENS_FILE, 0o600), (_LOCK_FILE, 0o600)):
        try:
            current = stat.S_IMODE(path.stat().st_mode)
        except OSError:
            continue  # missing, or not accessible: reported by _check_storage()
        if not current & 0o077:
            continue
        try:
            path.chmod(mode)
        except PermissionError:
            print(f"Warning: {path} is accessible by other users and can't be fixed "
                  f"(chmod {mode:o} it).", file=sys.stderr)


def _check_storage():
    """Fail fast, with a clear message, if the token files can't be used.

    Typical cause: res/ created by root while the server runs as another user.
    Without this check the server would start, then fail on every API call.
    """
    try:
        fd = os.open(_LOCK_FILE, os.O_RDONLY | os.O_CREAT, 0o600)
        try:
            _chown_to_res_owner(fd)
        finally:
            os.close(fd)
        if _TOKENS_FILE.exists():
            with open(_TOKENS_FILE, "r+", encoding="utf-8"):
                pass
        fd, tmp_path = tempfile.mkstemp(dir=_RES_PATH, prefix=".tokens.")
        os.close(fd)
        os.unlink(tmp_path)
    except OSError as exc:
        try:
            user = pwd.getpwuid(os.geteuid()).pw_name
        except KeyError:
            user = str(os.geteuid())
        print(f"Error: user '{user}' can't read/write the token files in {_RES_PATH}: {exc}\n"
              f"Fix: chown -R {user}: {_RES_PATH} && chmod 700 {_RES_PATH}", file=sys.stderr)
        sys.exit(1)


@contextlib.contextmanager
def _locked_tokens():
    with _tokens_lock:
        fd = os.open(_LOCK_FILE, os.O_RDONLY | os.O_CREAT, 0o600)
        try:
            _chown_to_res_owner(fd)
            fcntl.flock(fd, fcntl.LOCK_EX)
            yield
        finally:
            os.close(fd)  # releases the flock


def _read_tokens():
    """Return the list of (username, token_hash, created) entries.

    Lines in another format (e.g. plaintext tokens of older versions) are ignored
    and disappear at the next write.
    """
    entries = []
    try:
        file = open(_TOKENS_FILE, "r", encoding="utf-8")
    except FileNotFoundError:
        return entries
    with file:
        for line in file:
            parts = line.rstrip("\n").split("\t")
            if len(parts) != 3:
                continue
            username, token_hash, created = parts
            if not _is_valid_username(username) or not _TOKEN_RE.fullmatch(token_hash):
                continue
            try:
                entries.append((username, token_hash, int(created)))
            except ValueError:
                continue
    return entries


def _is_expired(created, now):
    # A creation date in the future (clock change, tampering) is not trusted.
    return now - created > _token_ttl or created > now + 300


def _write_tokens(entries, prune=True):
    """Atomically replace the tokens file (temporary file + rename, mode 0600)."""
    now = int(time.time())
    if prune:
        entries = [entry for entry in entries if not _is_expired(entry[2], now)]

    fd, tmp_path = tempfile.mkstemp(dir=_RES_PATH, prefix=".tokens.")  # mode 0600
    try:
        _chown_to_res_owner(fd)
        with os.fdopen(fd, "w", encoding="utf-8") as file:
            for username, token_hash, created in entries:
                file.write(f"{username}\t{token_hash}\t{created}\n")
            file.flush()
            os.fsync(file.fileno())
        os.replace(tmp_path, _TOKENS_FILE)
    except BaseException:
        with contextlib.suppress(FileNotFoundError):
            os.unlink(tmp_path)
        raise

    # Make the rename itself durable
    dir_fd = os.open(_RES_PATH, os.O_RDONLY)
    try:
        os.fsync(dir_fd)
    finally:
        os.close(dir_fd)


def _find_entry(entries, token, now):
    """Return the entry matching the (valid format) token, or None."""
    token_hash = _hash_token(token)
    for entry in entries:
        if hmac.compare_digest(entry[1], token_hash) and not _is_expired(entry[2], now):
            return entry
    return None


def _lookup_token(token):
    """Return the username associated with a valid, unexpired token, or None."""
    if not isinstance(token, str) or not _TOKEN_RE.fullmatch(token):
        return None
    with _locked_tokens():
        entries = _read_tokens()
    entry = _find_entry(entries, token, int(time.time()))
    return entry[0] if entry else None


def _consume_token(token):
    """Atomically remove the token from the file and return its entry, or None.

    Removing it *before* calling samba-tool means two concurrent requests can't
    both use the same token.
    """
    if not isinstance(token, str) or not _TOKEN_RE.fullmatch(token):
        return None
    with _locked_tokens():
        entries = _read_tokens()
        entry = _find_entry(entries, token, int(time.time()))
        if entry is not None:
            _write_tokens([e for e in entries if e is not entry])
    return entry


def _restore_token(entry):
    """Put a consumed token back (password change failed, the user can retry),
    unless a new token has been generated for this user in the meantime."""
    with _locked_tokens():
        entries = _read_tokens()
        if not any(e[0] == entry[0] for e in entries):
            entries.append(entry)
            _write_tokens(entries)


def _generate_token(username, is_ssl, fqdn):
    if not _is_valid_username(username):
        print(f"Invalid username: {username!r}", file=sys.stderr)
        sys.exit(2)

    token = secrets.token_hex(32)
    with _locked_tokens():
        # Only one token per user: a new token revokes the previous one.
        entries = [entry for entry in _read_tokens() if entry[0] != username]
        entries.append((username, _hash_token(token), int(time.time())))
        # The server prunes expired tokens with its own --token-ttl
        _write_tokens(entries, prune=False)

    protocol = "https" if is_ssl else "http"
    # The token is in the fragment (#): browsers never send it to the server,
    # so it does not end up in access logs or Referer headers.
    print(f"{protocol}://{fqdn}/#{token}")


# ---------------------------------------------------------------------------
# Web server
# ---------------------------------------------------------------------------

def _build_ssl_context(ssl_cert, ssl_key):
    """Create the server-side TLS context (replaces the removed ssl.wrap_socket())."""
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    # keyfile may be the same file as certfile (combined PEM)
    context.load_cert_chain(certfile=ssl_cert, keyfile=ssl_key)
    return context


class SmbpasswdHTTPServer(http.server.ThreadingHTTPServer):
    daemon_threads = True

    def __init__(self, server_address, handler, is_ssl,
                 max_connections=_DEFAULT_MAX_CONNECTIONS,
                 max_connections_per_ip=_DEFAULT_MAX_CONNECTIONS_PER_IP):
        super().__init__(server_address, handler)
        self.is_ssl = is_ssl
        self._max_connections = max_connections
        self._max_connections_per_ip = max_connections_per_ip
        self._conn_lock = threading.Lock()
        self._conn_total = 0
        self._conn_per_ip = {}

    def _acquire_slot(self, ip):
        with self._conn_lock:
            if (self._conn_total >= self._max_connections
                    or self._conn_per_ip.get(ip, 0) >= self._max_connections_per_ip):
                return False
            self._conn_total += 1
            self._conn_per_ip[ip] = self._conn_per_ip.get(ip, 0) + 1
            return True

    def _release_slot(self, ip):
        with self._conn_lock:
            self._conn_total -= 1
            count = self._conn_per_ip.get(ip, 0) - 1
            if count > 0:
                self._conn_per_ip[ip] = count
            else:
                self._conn_per_ip.pop(ip, None)

    def process_request(self, request, client_address):
        # Limit the connections handled simultaneously, in total and per client
        # IP, so a single client can't hold every slot.
        ip = client_address[0]
        if not self._acquire_slot(ip):
            if _verbose:
                print(f"{ip}: connection limit reached, connection dropped", flush=True)
            self.shutdown_request(request)
            return
        try:
            super().process_request(request, client_address)
        except BaseException:
            self._release_slot(ip)
            raise

    def process_request_thread(self, request, client_address):
        try:
            super().process_request_thread(request, client_address)
        finally:
            self._release_slot(client_address[0])

    def handle_error(self, request, client_address):
        # Failed handshakes, timeouts and disconnects are routine (scanners,
        # browsers closing connections): no traceback for those.
        exc = sys.exc_info()[1]
        if isinstance(exc, (ssl.SSLError, ConnectionError, TimeoutError)):
            if _verbose:
                print(f"{client_address[0]}: {exc.__class__.__name__}: {exc}", flush=True)
            return
        super().handle_error(request, client_address)


def _start_web_server(is_ssl, ssl_cert, ssl_key, address, port,
                      max_connections=_DEFAULT_MAX_CONNECTIONS,
                      max_connections_per_ip=_DEFAULT_MAX_CONNECTIONS_PER_IP):
    context = None
    if is_ssl:
        ssl_cert = _resolve_path(ssl_cert)
        ssl_key = _resolve_path(ssl_key)
        if not ssl_cert.is_file() or not ssl_key.is_file():
            print("SSL Certificate/Private Key not found!")
            sys.exit(1)
        if stat.S_IMODE(ssl_key.stat().st_mode) & 0o007:
            print(f"Warning: private key {ssl_key} is readable by all users (chmod 600 it).",
                  file=sys.stderr)
        try:
            context = _build_ssl_context(str(ssl_cert), str(ssl_key))
        except (ssl.SSLError, OSError) as exc:
            print(f"Could not load SSL Certificate/Private Key: {exc}")
            sys.exit(1)

    # Serve static files from the static folder without changing the working dir
    handler = functools.partial(SmbpasswdRequestHandler, directory=str(_STATIC_PATH))

    httpd = SmbpasswdHTTPServer((address, port), handler, is_ssl,
                                max_connections, max_connections_per_ip)

    if context is not None:
        # do_handshake_on_connect=False: the handshake is done in the request
        # thread (SmbpasswdRequestHandler.setup), with a timeout, instead of in
        # accept() where one silent client would block the whole server.
        httpd.socket = context.wrap_socket(httpd.socket, server_side=True,
                                           do_handshake_on_connect=False)

    protocol = "https" if is_ssl else "http"
    print(f"Listening on: {protocol}://{address}:{port}/", flush=True)
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        httpd.server_close()


class SmbpasswdRequestHandler(http.server.SimpleHTTPRequestHandler):

    # Applied to the connection socket by StreamRequestHandler.setup()
    timeout = _REQUEST_TIMEOUT

    def version_string(self):
        # Don't advertise the Python version in the Server header
        return "smbpasswd-web"

    def setup(self):
        super().setup()
        if isinstance(self.connection, ssl.SSLSocket):
            self.connection.do_handshake()

    def end_headers(self):
        for name, value in _SECURITY_HEADERS:
            self.send_header(name, value)
        if _hsts_max_age > 0 and getattr(self.server, "is_ssl", False):
            self.send_header("Strict-Transport-Security", f"max-age={_hsts_max_age}")
        super().end_headers()

    def invalid_api_request(self):
        self.send_error(HTTPStatus.BAD_REQUEST, "Invalid API request")

    def send_json(self, data, status=HTTPStatus.OK):
        body = json.dumps(data).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, format, *args):
        if _verbose:
            super().log_message(format, *args)

    def _call_tool(self, username, password):
        if not _is_valid_username(username) or not _is_valid_password(password):
            return False

        # The password is never put on the command line (visible in ps,
        # /proc/<pid>/cmdline and the sudo log): both tools read it twice on
        # stdin (new password + confirmation).
        if _use_samba_tool:
            args = ["samba-tool", "user", "setpassword", username]
        else:
            args = ["smbpasswd", "-s", username]
        input_data = f"{password}\n{password}\n".encode("utf-8")

        if _use_sudo:
            args = ["sudo", "-n"] + args

        tool = args[2] if _use_sudo else args[0]
        try:
            proc = subprocess.run(
                args,
                input=input_data,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.PIPE,
                timeout=60,
                check=False,
                # New session = no controlling terminal: samba-tool's getpass()
                # can't open /dev/tty and reads the password from stdin.
                start_new_session=True,
            )
        except (OSError, ValueError, subprocess.SubprocessError):
            print("Failed to change user password!")
            traceback.print_exc(file=sys.stdout)
            return False

        if proc.returncode == 0:
            print(f"Password changed for user {username}", flush=True)
            return True

        print(f"{tool} returned {proc.returncode} for user {username}")
        print("stderr:", proc.stderr.decode("utf-8", errors="replace"), flush=True)
        return False

    def api_get_username(self, json_body):
        """Return the username for a given token"""

        username = _lookup_token(json_body.get("token"))
        if username is None:
            self.invalid_api_request()
            return

        self.send_json({"username": username})

    def api_set_password(self, json_body):
        """Define the user's smb password"""

        token = json_body.get("token")
        password = json_body.get("password")
        if not isinstance(token, str) or not _is_valid_password(password):
            self.invalid_api_request()
            return

        entry = _consume_token(token)
        if entry is None:
            self.invalid_api_request()
            return

        if self._call_tool(entry[0], password):
            self.send_json({"status": "OK"})
        else:
            # e.g. rejected by the password policy: let the user try again
            _restore_token(entry)
            self.send_error(HTTPStatus.INTERNAL_SERVER_ERROR, "Could not set password.")

    def _read_json_body(self):
        """Read and decode the JSON request body; return None if invalid."""
        try:
            content_length = int(self.headers.get("Content-Length", ""))
        except ValueError:
            return None
        if content_length <= 0 or content_length > _MAX_BODY_SIZE:
            return None

        try:
            json_body = json.loads(self.rfile.read(content_length).decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError):
            return None
        return json_body if isinstance(json_body, dict) else None

    def do_POST(self):
        """Process API"""

        if not self.path.startswith("/api/"):
            # SimpleHTTPRequestHandler has no do_POST(): answer properly
            # instead of crashing with AttributeError.
            self.send_error(HTTPStatus.NOT_IMPLEMENTED, "Unsupported method (POST)")
            return

        json_body = self._read_json_body()
        if json_body is None:
            self.invalid_api_request()
            return

        endpoint = self.path[len("/api/"):].split("?", 1)[0].strip("/")
        if endpoint == "get_username":
            self.api_get_username(json_body)
        elif endpoint == "set_password":
            self.api_set_password(json_body)
        else:
            self.invalid_api_request()

    def list_directory(self, path):
        """Disable directory listing"""
        self.send_error(HTTPStatus.FORBIDDEN, "Directory listing forbidden.")
        return None


def main():
    global _use_sudo
    global _use_samba_tool
    global _verbose
    global _token_ttl
    global _hsts_max_age

    parser = argparse.ArgumentParser(
        description="Web interface to change samba user's password", formatter_class=argparse.ArgumentDefaultsHelpFormatter)

    subparsers = parser.add_subparsers(dest="command", help="Commands available")

    # Server command
    parser_server = subparsers.add_parser("server", help="Start the webserver")
    parser_server.add_argument("-a", "--address", help="Address to bind", default=_DEFAULT_ADDRESS)
    parser_server.add_argument("-p", "--port", type=int,
                               help=f"Port number to bind (default: If SSL, {_DEFAULT_HTTPS_PORT}, otherwise {_DEFAULT_HTTP_PORT})")

    parser_server.add_argument("-v", "--verbose", help="Log HTTP requests", action="store_true")

    parser_server.add_argument("--sudo", help="Use sudo to call smbpasswd/samba-tool", action="store_true")

    parser_server.add_argument("--samba-tool", help="Use samba-tool instead smbpasswd", action="store_true")

    parser_server.add_argument("--ssl", help="Start webserver using SSL", action="store_true")
    parser_server.add_argument("--ssl-cert", help="SSL certificate to use", default=_DEFAULT_SSL_CERT)
    parser_server.add_argument("--ssl-key", help="SSL certificate private key", default=_DEFAULT_SSL_KEY)

    parser_server.add_argument("--token-ttl", type=float, default=_DEFAULT_TOKEN_TTL_HOURS,
                               help=f"Validity of a token, in hours (max {_MAX_TOKEN_TTL_HOURS})")

    parser_server.add_argument("--max-conn", type=int, default=_DEFAULT_MAX_CONNECTIONS,
                               help="Maximum number of simultaneous connections")
    parser_server.add_argument("--max-conn-per-ip", type=int, default=_DEFAULT_MAX_CONNECTIONS_PER_IP,
                               help="Maximum number of simultaneous connections per client IP "
                                    "(behind a reverse proxy all clients share the proxy's IP)")

    parser_server.add_argument("--hsts-max-age", type=int, default=0,
                               help="Send Strict-Transport-Security with this max-age (seconds) "
                                    "in SSL mode; 0 = disabled. HSTS applies to every port of "
                                    "the host name, enable it only if nothing on this host name "
                                    "uses plain http")

    # Token command
    parser_token = subparsers.add_parser("gen-token", help="Generate a token to a username")
    parser_token.add_argument("--ssl", help="Use https protocol on the generated URL", action="store_true")
    parser_token.add_argument("--fqdn", help="Use this FQDN instead the default one", default=socket.getfqdn())
    parser_token.add_argument("username", metavar="USERNAME", help="Username")

    # Parse arguments
    _args = parser.parse_args()

    if _args.command not in ("server", "gen-token"):
        parser.print_help()
        sys.exit(1)

    # Validate options before touching any file
    if _args.command == "server":
        ttl = _args.token_ttl
        if not math.isfinite(ttl) or not 0 < ttl <= _MAX_TOKEN_TTL_HOURS:
            parser.error(f"--token-ttl must be between 0 and {_MAX_TOKEN_TTL_HOURS} hours")
        if _args.max_conn < 1 or _args.max_conn_per_ip < 1:
            parser.error("--max-conn and --max-conn-per-ip must be at least 1")
        if _args.hsts_max_age < 0:
            parser.error("--hsts-max-age can't be negative")

    # Every file created from now on is private to the user running the app
    os.umask(0o077)
    try:
        _prepare_storage()
    except OSError as exc:
        print(f"Error: can't create {_RES_PATH}: {exc}", file=sys.stderr)
        sys.exit(1)
    _check_storage()

    if _args.command == "server":
        # If we should print HTTP requests
        _verbose = _args.verbose
        _token_ttl = int(_args.token_ttl * 3600)
        _hsts_max_age = _args.hsts_max_age

        port = _args.port
        if port is None:
            port = _DEFAULT_HTTPS_PORT if _args.ssl else _DEFAULT_HTTP_PORT

        _use_sudo = _args.sudo
        _use_samba_tool = _args.samba_tool
        _start_web_server(_args.ssl, _args.ssl_cert, _args.ssl_key, _args.address, port,
                          _args.max_conn, _args.max_conn_per_ip)
    else:
        _generate_token(_args.username, _args.ssl, _args.fqdn)


if __name__ == "__main__":
    main()
