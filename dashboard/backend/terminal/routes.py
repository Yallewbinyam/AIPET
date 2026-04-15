import os
import pty
import select
import subprocess
import termios
import struct
import fcntl
import signal
from flask import request
from flask_socketio import SocketIO, emit, disconnect
from flask_jwt_extended import decode_token
from jwt.exceptions import InvalidTokenError

# Store active terminal sessions
terminal_sessions = {}

def register_terminal(socketio):
    """Register terminal WebSocket events with SocketIO instance."""

    @socketio.on('connect', namespace='/terminal')
    def handle_connect():
        """Authenticate user and establish terminal session."""
        token = request.args.get('token')
        if not token:
            disconnect()
            return False
        try:
            decoded = decode_token(token)
            user_id = decoded.get('sub')
            if not user_id:
                disconnect()
                return False
        except Exception:
            disconnect()
            return False

        sid = request.sid

        # Spawn a real PTY shell
        master_fd, slave_fd = pty.openpty()
        process = subprocess.Popen(
            ['/bin/bash'],
            stdin=slave_fd,
            stdout=slave_fd,
            stderr=slave_fd,
            close_fds=True,
            env={
                'TERM': 'xterm-256color',
                'HOME': '/home/binyam',
                'PATH': '/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin',
                'USER': 'aipet',
                'SHELL': '/bin/bash',
                'PS1': r'\[\033[01;32m\]aipet@terminal\[\033[00m\]:\[\033[01;34m\]\w\[\033[00m\]\$ ',
            }
        )

        terminal_sessions[sid] = {
            'master_fd': master_fd,
            'slave_fd': slave_fd,
            'process': process,
            'user_id': user_id,
        }

        # Start reading output in background
        socketio.start_background_task(read_output, sid, master_fd, socketio)

    @socketio.on('input', namespace='/terminal')
    def handle_input(data):
        """Forward user keystrokes to the shell."""
        sid = request.sid
        session = terminal_sessions.get(sid)
        if session:
            try:
                os.write(session['master_fd'], data.encode())
            except OSError:
                pass

    @socketio.on('resize', namespace='/terminal')
    def handle_resize(data):
        """Handle terminal window resize."""
        sid = request.sid
        session = terminal_sessions.get(sid)
        if session:
            try:
                rows = data.get('rows', 24)
                cols = data.get('cols', 80)
                fcntl.ioctl(
                    session['master_fd'],
                    termios.TIOCSWINSZ,
                    struct.pack('HHHH', rows, cols, 0, 0)
                )
            except OSError:
                pass

    @socketio.on('disconnect', namespace='/terminal')
    def handle_disconnect():
        """Clean up terminal session on disconnect."""
        sid = request.sid
        session = terminal_sessions.pop(sid, None)
        if session:
            try:
                session['process'].terminate()
                os.close(session['master_fd'])
                os.close(session['slave_fd'])
            except OSError:
                pass


def read_output(sid, master_fd, socketio):
    """Background task: read shell output and send to browser."""
    while True:
        try:
            r, _, _ = select.select([master_fd], [], [], 0.1)
            if r:
                output = os.read(master_fd, 4096)
                if output:
                    socketio.emit('output', output.decode('utf-8', errors='replace'), namespace='/terminal', room=sid)
                else:
                    break
        except OSError:
            break
    # Session ended
    terminal_sessions.pop(sid, None)
    socketio.emit('disconnected', namespace='/terminal', room=sid)


def init_terminal(app, jwt_secret):
    """Initialize SocketIO with terminal support."""
    from flask_socketio import SocketIO
    socketio = SocketIO(
        app,
        cors_allowed_origins="*",
        async_mode='eventlet',
        logger=False,
        engineio_logger=False
    )
    register_terminal(socketio)
    return socketio
