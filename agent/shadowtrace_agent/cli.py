"""ShadowTrace agent command line.

python -m shadowtrace_agent -c config.local.yaml enroll --token ste_...
python -m shadowtrace_agent -c config.local.yaml run
python -m shadowtrace_agent -c config.local.yaml status
"""

import argparse
import sys
from pathlib import Path

from shadowtrace_agent import __version__
from shadowtrace_agent.agent import Agent, enroll, setup_logging
from shadowtrace_agent.config import load_config
from shadowtrace_agent.state import load_state
from shadowtrace_agent.transport.buffer import EventBuffer
from shadowtrace_agent.transport.client import ServerError


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="shadowtrace-agent")
    parser.add_argument("-c", "--config", type=Path, default=Path("config.yaml"))
    parser.add_argument("--version", action="version", version=__version__)
    sub = parser.add_subparsers(dest="command", required=True)
    enroll_cmd = sub.add_parser("enroll", help="register this machine with the server")
    enroll_cmd.add_argument("--token", help="enrollment token (default: from config)")
    enroll_cmd.add_argument("--token-stdin", action="store_true", help="read token from stdin")
    enroll_cmd.add_argument("--server", help="server URL (default: from config)")
    sub.add_parser("run", help="start monitoring")
    sub.add_parser("status", help="show enrollment and buffer state")
    args = parser.parse_args(argv)

    config = load_config(args.config)
    data_dir = config.resolved_data_dir

    match args.command:
        case "enroll":
            if args.server:
                config.server_url = args.server
            if args.token and args.token_stdin:
                parser.error("use only one token source")
            token = (
                sys.stdin.readline().strip()
                if args.token_stdin
                else (args.token or config.enrollment_token)
            )
            if not token:
                parser.error("an enrollment token is required (--token or config)")
            try:
                state = enroll(config, token)
            except ServerError as exc:
                print(f"Enrollment failed: {exc}")
                return 1
            print(f"Enrolled as {state.device_id} with {state.server_url}")
        case "run":
            setup_logging(data_dir, config.log_level)
            Agent(config).run()
        case "status":
            state = load_state(data_dir)
            print(f"Data directory: {data_dir}")
            print(f"Enrolled:       {state.device_id if state else 'no'}")
            print(f"Server:         {state.server_url if state else config.server_url}")
            buffer_path = data_dir / "buffer.db"
            if buffer_path.exists():
                buffer = EventBuffer(buffer_path)
                print(f"Buffered:       {len(buffer)} event(s) waiting to upload")
                buffer.close()
    return 0
