import logging
import re
import socket

# DXSpider's internal client port (the one console.pl / winclient.pl use). It only
# listens on 127.0.0.1 and trusts the callsign it is given without a password, so a
# priv-9 user logged in here keeps its sysop privileges - unlike a telnet login on
# the public port, where priv is only kept after a password login.
CONSOLE_TIMEOUT = 15  # seconds per read before giving up

_MSG_RE = re.compile(rb"^(\w)([^|]+)\|(.*)$")
_ESC_RE = re.compile(r"%([0-9A-F]{2})")

# What DXSpider answers when the user's privilege is too low ('e5' / 'sorry' msgs)
NOT_ALLOWED_RE = re.compile(r"^(Not Allowed|Sorry)", re.MULTILINE)


def run_console_commands(host, port, call, commands):
    """Log in to DXSpider's local client port as `call`, run each command and
    return a list with the output text of every command (same order), or None if
    the connection/login failed."""
    call = call.upper()
    prompt_re = re.compile(rf"^{re.escape(call)} de \S+\s+\d+-\w\w\w-\d+\s+\d+Z")
    sock = None
    try:
        sock = socket.create_connection((host, int(port)), timeout=CONSOLE_TIMEOUT)
        f = sock.makefile("rwb")

        def send(line):
            f.write(line.encode("utf-8") + b"\n")
            f.flush()

        def read_until_prompt():
            out = []
            while True:
                raw = f.readline()
                if not raw:
                    raise EOFError("console connection closed")
                m = _MSG_RE.match(raw.rstrip(b"\r\n"))
                if not m:
                    continue
                sort = m.group(1).decode()
                line = _ESC_RE.sub(lambda x: chr(int(x.group(1), 16)),
                                   m.group(3).decode("utf-8", errors="replace"))
                if sort == "Z":
                    raise EOFError("disconnected by DXSpider")
                if sort in ("E", "B"):
                    continue
                if prompt_re.match(line):
                    return "\n".join(out)
                out.append(line)

        send(f"A{call}|local")
        read_until_prompt()
        results = []
        for cmd in commands:
            send(f"I{call}|{cmd}")
            results.append(read_until_prompt())
        send(f"I{call}|bye")
        return results
    except Exception as e:
        logging.error(f"run_console_commands error: {e}")
        return None
    finally:
        if sock:
            sock.close()
