import telnetlib3
import asyncio
import struct
import logging
import re

WAIT_LOGIN = b"login:"
WAIT_PASS  = b"password:"
WAIT_FOR   = b"dxspider >"

LOGIN_TIMEOUT    = 10  # seconds to wait for the login: prompt after connecting
PASSWORD_TIMEOUT = 5   # seconds to wait for the password: prompt
PROMPT_TIMEOUT   = 10  # seconds to wait for the dxspider > prompt after login/each command


async def _telnet_login(host, port, user, password=None):
    """Open a telnet connection to a local DXSpider node and log in.
    Every step is bounded by a timeout so a silent/hung peer can't hang the caller
    forever. Raises asyncio.TimeoutError/OSError/EOFError on failure; on success
    returns (reader, writer) positioned at the dxspider > prompt. Caller must close
    reader/writer."""
    reader, writer = await telnetlib3.open_connection(host, int(port), encoding=None)
    try:
        await asyncio.wait_for(reader.readuntil(WAIT_LOGIN), timeout=LOGIN_TIMEOUT)
        writer.write(user.encode("utf-8") + b"\n")
        if password:
            await asyncio.wait_for(reader.readuntil(WAIT_PASS), timeout=PASSWORD_TIMEOUT)
            writer.write(password.encode("utf-8") + b"\n")
        await asyncio.wait_for(reader.readuntil(WAIT_FOR), timeout=PROMPT_TIMEOUT)
    except Exception:
        writer.close()
        reader.feed_eof()
        raise
    return reader, writer


def decode_telnet(data):
    """Accept UTF-8 and legacy single-byte names in DXSpider output."""
    try:
        return data.decode("utf-8")
    except UnicodeDecodeError:
        return data.decode("latin-1")


def parse_who(lines):
    # Split fixed-width fields before decoding: names may contain multibyte text.
    if isinstance(lines, str):
        lines = lines.encode("utf-8")
    row_headers = ("callsign", "type", "state", "started", "name", "average_rtt", "link")
    payload = []
    for line in lines.splitlines():
        parts = line.lstrip().split(b" ", 1)
        if len(parts) != 2 or parts[0] == b"Callsign":
            continue
        call, rest = parts
        if len(rest) <= 32:
            continue
        fields = [decode_telnet(call)]
        rest += b" " * 50
        fields += [decode_telnet(field).strip() for field in
                   struct.Struct("10s 8s 18s 11s 2x 5s").unpack_from(rest)]
        payload.append(dict(zip(row_headers, fields)))
    return payload

async def fetch_who_and_version(host, port, user, password=None):
    logging.debug(f"Connecting to {host}:{port} for WHO and SH/VERSION")
    who_data = ""
    version_info = "Unknown"
    reader = writer = None

    try:
        reader, writer = await _telnet_login(host, port, user, password)
        logging.debug("Login successful")

        writer.write(b'who\n')
        who_response = await asyncio.wait_for(reader.readuntil(WAIT_FOR), timeout=PROMPT_TIMEOUT)
        who_data = who_response

        writer.write(b'sh/version\n')
        version_response = await asyncio.wait_for(reader.readuntil(WAIT_FOR), timeout=PROMPT_TIMEOUT)
        res = decode_telnet(version_response).strip().splitlines()
        logging.debug(f"Full SH/VERSION Response:\n{res}")

        for line in res:
            logging.debug(f"Processing Line: {line}")
            match = re.search(r"DXSpider v([\d.]+) \(build (\d+)", line)
            if match:
                version_info = f"DXSpider v{match.group(1)} build {match.group(2)}"
                logging.debug(f"Extracted DXSpider Version: {version_info}")
                break
        else:
            logging.debug("No valid DXSpider version found in the response.")

    except asyncio.TimeoutError:
        logging.error("Timeout during WHO/version telnet session")
        raise
    except EOFError:
        logging.error("End of buffer reached unexpectedly")
        raise
    except Exception as e:
        logging.error(f"Error retrieving WHO and version info: {e}")
        raise
    finally:
        if writer:
            writer.close()
        if reader:
            reader.feed_eof()
        logging.debug("Connection closed")

    parsed = parse_who(who_data)
    if not parsed:
        raise ValueError("WHO response contains no valid rows")
    return parsed, version_info


async def run_sysop_command(host, port, user, password, command):
    """Login to local DXSpider via telnet, run one sysop command, return response text."""
    reader = writer = None
    try:
        reader, writer = await _telnet_login(host, port, user, password)
        writer.write(command.encode("utf-8") + b"\n")
        raw = await asyncio.wait_for(reader.readuntil(WAIT_FOR), timeout=PROMPT_TIMEOUT)
        return raw.decode("utf-8").strip()
    except Exception as e:
        logging.error(f"run_sysop_command error: {e}")
        return None
    finally:
        if writer:
            writer.close()
        if reader:
            reader.feed_eof()
