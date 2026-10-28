import json
from dataclasses import asdict, dataclass
from pathlib import Path

STATE_FILE = "state.json"


@dataclass
class EnrollmentState:
    device_id: str
    api_key: str
    server_url: str


def load_state(data_dir: Path) -> EnrollmentState | None:
    path = data_dir / STATE_FILE
    if not path.exists():
        return None
    return EnrollmentState(**json.loads(path.read_text(encoding="utf-8")))


def save_state(data_dir: Path, state: EnrollmentState) -> None:
    # TODO(phase 7): protect the API key with DPAPI on Windows and restrict ACLs on data_dir.
    data_dir.mkdir(parents=True, exist_ok=True)
    tmp = data_dir / (STATE_FILE + ".tmp")
    tmp.write_text(json.dumps(asdict(state), indent=2), encoding="utf-8")
    tmp.replace(data_dir / STATE_FILE)
