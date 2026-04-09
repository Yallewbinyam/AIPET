import os
import pty
import select
import subprocess
import struct
import fcntl
import termios
import jwt
from flask import request
from flask_socketio import SocketIO, disconnect

def init_terminal(app, secret_key):
    socketio = SocketIO(app, 
                       cors_allowed_origins="*", 
                       async_mode="eventlet",
                       logger=False,
                       engineio_logger=False)
    fd_map = {}

    def verify_token(token):
        try:
            # Try Flask-JWT-Extended format first (sub field)
            data = jwt.decode(token, secret_key, algorithms=["HS256"])
            return data.get("sub") or data.get("user_id") or data.get("identity")
        except Exception as e:
            print(f"Token verification error: {e}")
            return None

    @socketio.on("connect", namespace="/terminal")
    def on_connect():
        token = request.args.get("token")
        if not verify_token(token):
            return False
        sid = request.sid
        master_fd, slave_fd = pty.openpty()
        proc = subprocess.Popen(
            ["/bin/bash", "--login"],
            stdin=slave_fd,
            stdout=slave_fd,
            stderr=slave_fd,
            close_fds=True,
            env={**os.environ, "TERM": "xterm-256color", "COLORTERM": "truecolor"},
        )
        os.close(slave_fd)
        fd_map[sid] = {"fd": master_fd, "proc": proc}

        import eventlet
        def read_output():
            while sid in fd_map:
                try:
                    r, _, _ = select.select([master_fd], [], [], 0.05)
                    if r:
                        data = os.read(master_fd, 1024)
                        if data:
                            socketio.emit("output", {"data": data.decode("utf-8", errors="replace")}, namespace="/terminal", to=sid)
                except Exception:
                    break
        eventlet.spawn(read_output)

    @socketio.on("input", namespace="/terminal")
    def on_input(data):
        sid = request.sid
        if sid in fd_map:
            try:
                os.write(fd_map[sid]["fd"], data["data"].encode())
            except Exception:
                pass

    @socketio.on("resize", namespace="/terminal")
    def on_resize(data):
        sid = request.sid
        if sid in fd_map:
            try:
                winsize = struct.pack("HHHH", data["rows"], data["cols"], 0, 0)
                fcntl.ioctl(fd_map[sid]["fd"], termios.TIOCSWINSZ, winsize)
            except Exception:
                pass

    @socketio.on("disconnect", namespace="/terminal")
    def on_disconnect():
        sid = request.sid
        if sid in fd_map:
            try:
                fd_map[sid]["proc"].terminate()
                os.close(fd_map[sid]["fd"])
            except Exception:
                pass
            del fd_map[sid]

    return socketio
