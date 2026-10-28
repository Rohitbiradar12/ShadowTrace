from typing import Any

import httpx

API_PREFIX = "/api/v1"


class ServerError(Exception):
    """The server could not be reached or returned an unexpected error. Retry later."""


class AuthError(ServerError):
    """The server rejected our credentials. Retrying will not help until re-enrollment."""


class ServerClient:
    def __init__(
        self,
        server_url: str,
        verify: bool | str = True,
        api_key: str | None = None,
        timeout: float = 10.0,
        transport: httpx.BaseTransport | None = None,
    ) -> None:
        headers = {"X-Device-Key": api_key} if api_key else {}
        self._http = httpx.Client(
            base_url=server_url.rstrip("/") + API_PREFIX,
            headers=headers,
            verify=verify,
            timeout=timeout,
            transport=transport,
        )

    def enroll(self, token: str, info: dict[str, Any]) -> dict[str, Any]:
        return self._post("/agents/enroll", {"enrollment_token": token, **info})

    def heartbeat(self, payload: dict[str, Any]) -> dict[str, Any]:
        return self._post("/agents/heartbeat", payload)

    def upload(self, events: list[dict[str, Any]]) -> dict[str, Any]:
        return self._post("/events/batch", {"events": events})

    def close(self) -> None:
        self._http.close()

    def _post(self, path: str, body: dict[str, Any]) -> dict[str, Any]:
        try:
            response = self._http.post(path, json=body)
        except httpx.HTTPError as exc:
            raise ServerError(f"{path}: {exc}") from exc
        if response.status_code in (401, 403):
            raise AuthError(f"{path}: {response.status_code} {response.text}")
        if response.is_error:
            raise ServerError(f"{path}: {response.status_code} {response.text}")
        return response.json()
