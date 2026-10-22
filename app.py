#!/usr/bin/env python3
"""smbpasswd-web is a simple web interface to smbpasswd.

The only purpose is to allow a user to change its samba password using a webbrowser,
no user adding, no machine account, nothing, plain simple changing a password.

Requires Python >= 3.8 (tested on 3.12 / 3.13).
"""

import argparse
import functools
import hashlib
import hmac
import http.server
import json
import os
import socket
import ssl
import subprocess
import sys
import threading
import traceback
from http import HTTPStatus
from pathlib import Path

__author__ = "Tercio Gaudencio FIlho"
__copyright__ = "Copyright 2019, Tercio Gaudencio Filho"
__credits__ = ["Tercio Gaudencio Filho"]
__license__ = "MIT"
__version__ = "1.1.0"
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

# Maximum accepted size of an API request body (bytes)
_MAX_BODY_SIZE = 64 * 1024

_use_sudo = False
_use_samba_tool = False
_verbose = False

# Serialises access to the tokens file now that requests are handled in threads
_tokens_lock = threading.Lock()


def _resolve_path(path):
    """Resolve a user-supplied path relative to the app folder if it is not absolute."""
    path = Path(path)
    return path if path.is_absolute() else _APP_PATH / path


def _read_tokens():
    """Return the list of (username, token) pairs stored in the tokens file."""
    entries = []
    with open(_TOKENS_FILE, "r", encoding="utf-8") as file:
        for line in file:
            parts = line.rstrip("\n").split("\t")
            if len(parts) == 2 and parts[0] and parts[1]:
                entries.append((parts[0], parts[1]))
    return entries


def _build_ssl_context(ssl_cert, ssl_key):
    """Create the server-side TLS context (replaces the removed ssl.wrap_socket())."""
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    # keyfile may be the same file as certfile (combined PEM)
    context.load_cert_chain(certfile=ssl_cert, keyfile=ssl_key)
    return context


def _start_web_server(is_ssl, ssl_cert, ssl_key, address, port):
    context = None
    if is_ssl:
        ssl_cert = _resolve_path(ssl_cert)
        ssl_key = _resolve_path(ssl_key)
        if not ssl_cert.is_file() or not ssl_key.is_file():
            print("SSL Certificate/Private Key not found!")
            sys.exit(1)
        try:
            context = _build_ssl_context(str(ssl_cert), str(ssl_key))
        except (ssl.SSLError, OSError) as exc:
            print(f"Could not load SSL Certificate/Private Key: {exc}")
            sys.exit(1)

    # Serve static files from the static folder without changing the working dir
    handler = functools.partial(SmbpasswdRequestHandler, directory=str(_STATIC_PATH))

    # ThreadingHTTPServer: one slow or stuck client (e.g. an unfinished TLS
    # handshake) no longer blocks every other request.
    httpd = http.server.ThreadingHTTPServer((address, port), handler)
    httpd.daemon_threads = True

    if context is not None:
        httpd.socket = context.wrap_socket(httpd.socket, server_side=True)

    protocol = "https" if is_ssl else "http"
    print(f"Listening on: {protocol}://{address}:{port}/", flush=True)
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        httpd.server_close()


def _generate_token(username, is_ssl, fqdn):
    # TODO: Validate the username provided

    with _tokens_lock:
        token = None
        for user, user_token in _read_tokens():
            if user == username:
                token = user_token
                break

        if token is None:
            token = hashlib.sha256(username.encode() + os.urandom(32)).hexdigest()

            with open(_TOKENS_FILE, "a", encoding="utf-8") as file:
                file.write(f"{username}\t{token}\n")

    protocol = "https" if is_ssl else "http"
    print(f"{protocol}://{fqdn}/?{token}")


class SmbpasswdRequestHandler(http.server.SimpleHTTPRequestHandler):

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
        input_param = None
        if _use_samba_tool:
            # "--newpassword=<pw>" in one argument, so a password starting with
            # "-" can't be misread as an option.
            args = ["samba-tool", "user", "setpassword", username, f"--newpassword={password}"]
        else:
            args = ["smbpasswd", "-s", username]
            input_param = (password + "\n" + password + "\n").encode()

        if _use_sudo:
            args = ["sudo", "-n"] + args

        tool = args[2] if _use_sudo else args[0]
        try:
            proc = subprocess.run(
                args,
                input=input_param,
                stdin=None if input_param is not None else subprocess.DEVNULL,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.PIPE,
                timeout=60,
                check=False,
            )
        except (OSError, subprocess.SubprocessError):
            print("Failed to change user password!")
            traceback.print_exc(file=sys.stdout)
            return False

        if proc.returncode == 0:
            return True

        print(f"{tool} returned", proc.returncode)
        print("stderr:", proc.stderr.decode("utf-8", errors="replace"))
        return False

    def get_username(self, provided_token):
        """Return the username associated with the provided token"""

        if not isinstance(provided_token, str) or not provided_token:
            return None

        with _tokens_lock:
            entries = _read_tokens()

        for username, token in entries:
            if hmac.compare_digest(token.encode(), provided_token.encode()):
                return username
        return None

    def remove_token(self, provided_token):
        """Remove a token that has been used"""

        with _tokens_lock:
            entries = _read_tokens()
            with open(_TOKENS_FILE, "w", encoding="utf-8") as file:
                for username, token in entries:
                    if token != provided_token:
                        file.write(f"{username}\t{token}\n")

    def api_get_username(self, json_body):
        """Return the username for a given token"""

        username = self.get_username(json_body.get("token"))
        if username is None:
            self.invalid_api_request()
            return

        self.send_json({"username": username})

    def api_set_password(self, json_body):
        """Define the user's smb password"""

        token = json_body.get("token")
        password = json_body.get("password")
        if not isinstance(token, str) or not isinstance(password, str) or not password:
            self.invalid_api_request()
            return

        username = self.get_username(token)
        if username is None:
            self.invalid_api_request()
            return

        if self._call_tool(username, password):
            self.remove_token(token)
            self.send_json({"status": "OK"})
        else:
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

    # Token command
    parser_token = subparsers.add_parser("gen-token", help="Generate a token to a username")
    parser_token.add_argument("--ssl", help="Use https protocol on the generated URL", action="store_true")
    parser_token.add_argument("--fqdn", help="Use this FQDN instead the default one", default=socket.getfqdn())
    parser_token.add_argument("username", metavar="USERNAME", help="Username")

    # Parse arguments
    _args = parser.parse_args()

    _RES_PATH.mkdir(exist_ok=True)
    _TOKENS_FILE.touch(exist_ok=True)

    if _args.command == "server":
        # If we should print HTTP requests
        _verbose = _args.verbose

        port = _args.port
        if port is None:
            port = _DEFAULT_HTTPS_PORT if _args.ssl else _DEFAULT_HTTP_PORT

        _use_sudo = _args.sudo
        _use_samba_tool = _args.samba_tool
        _start_web_server(_args.ssl, _args.ssl_cert, _args.ssl_key, _args.address, port)
    elif _args.command == "gen-token":
        _generate_token(_args.username, _args.ssl, _args.fqdn)
    else:
        parser.print_help()
        sys.exit(1)


if __name__ == "__main__":
    main()
