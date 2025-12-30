"""Async Discopanel API client."""

import aiohttp
import asyncio
import logging
from dataclasses import dataclass
from typing import Any, Dict, Optional, Union

logger = logging.getLogger(__name__)


def redact_authorization(headers: Dict[str, str]) -> Dict[str, str]:
    """Return a copy of headers with Authorization value redacted (case-insensitive)."""
    redacted = headers.copy()
    for key in redacted.keys():
        if key.lower() == "authorization":
            redacted[key] = "REDACTED"
    return redacted


def _first(payload: Dict[str, Any], keys: list[str]) -> Optional[Any]:
    for key in keys:
        if key in payload and payload[key] is not None:
            return payload[key]
    return None


def _safe_int(value: Any) -> Optional[int]:
    if value is None:
        return None
    try:
        return int(value)
    except (TypeError, ValueError):
        if isinstance(value, str):
            segment = value.split("/")[0]
            num = "".join(ch for ch in segment if ch.isdigit() or ch == "-")
            if num:
                try:
                    return int(num)
                except ValueError:
                    return None
    return None


def _safe_float(value: Any) -> Optional[float]:
    if value is None:
        return None
    try:
        return float(value)
    except (TypeError, ValueError):
        if isinstance(value, str):
            digits = "".join(ch for ch in value if (ch.isdigit() or ch in ".-"))
            try:
                return float(digits)
            except ValueError:
                return None
    return None


@dataclass
class ServerInfo:
    id: str
    name: str
    status: str
    mc_version: Optional[str] = None
    mod_loader: Optional[str] = None
    players_online: Optional[int] = None
    max_players: Optional[int] = None
    cpu_percent: Optional[float] = None
    memory_usage: Optional[int] = None  # bytes if provided
    memory: Optional[int] = None  # configured memory (MB)
    tps: Optional[float] = None


@dataclass
class ApiResponse:
    success: bool
    message: str
    data: Optional[Any] = None
    error_code: Optional[int] = None


class DiscopanelAPIError(Exception):
    def __init__(self, message: str, status_code: Optional[int] = None):
        super().__init__(message)
        self.status_code = status_code


class DiscopanelAPITimeoutError(DiscopanelAPIError):
    pass


class DiscopanelAPIConnectionError(DiscopanelAPIError):
    pass


class DiscopanelAPI:
    """Async wrapper for the Discopanel HTTP API."""

    def __init__(
        self,
        base_url: str,
        token_or_manager: Optional[Union[str, Any]] = None,
        api_prefix: str = ""
    ) -> None:
        if not token_or_manager:
            raise ValueError("An API token or TokenManager must be provided")

        self.base_url = base_url.rstrip("/")
        self.api_prefix = api_prefix.rstrip("/")
        self.token_or_manager = token_or_manager
        self.session: Optional[aiohttp.ClientSession] = None
        self.auth_token: Optional[str] = None

    async def __aenter__(self) -> "DiscopanelAPI":
        async def _log_start(session: aiohttp.ClientSession, ctx, params: aiohttp.TraceRequestStartParams):
            logger.debug(f"Starting request to {params.url}")
            await asyncio.sleep(0)

        async def _log_end(session: aiohttp.ClientSession, ctx, params: aiohttp.TraceRequestEndParams):
            logger.debug(f"Request to {params.url} ended with status {params.response.status}")
            await asyncio.sleep(0)

        trace_config = aiohttp.TraceConfig()
        trace_config.on_request_start.append(_log_start)
        trace_config.on_request_end.append(_log_end)

        connector = aiohttp.TCPConnector(limit=10, ssl=False)
        self.session = aiohttp.ClientSession(
            connector=connector,
            timeout=aiohttp.ClientTimeout(total=30, sock_connect=5, sock_read=20),
            trace_configs=[trace_config]
        )
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb) -> None:
        if self.session:
            await self.session.close()

    async def _get_auth_token(self) -> str:
        if isinstance(self.token_or_manager, str):
            auth_token = self.token_or_manager or self.auth_token
        elif hasattr(self.token_or_manager, "get_token"):
            auth_token = await self.token_or_manager.get_token()  # type: ignore
        else:
            auth_token = self.auth_token

        if not auth_token:
            raise DiscopanelAPIError("No authentication token available")

        return auth_token

    def _build_request_headers(self, auth_token: str, extra: Optional[Dict[str, str]] = None) -> Dict[str, str]:
        headers = {
            "Authorization": f"Bearer {auth_token}",
            "Content-Type": "application/json"
        }
        if extra:
            headers.update(extra)
        return headers

    async def _execute_request(
        self,
        session: aiohttp.ClientSession,
        method: str,
        url: str,
        headers: Dict[str, str],
        **kwargs
    ) -> ApiResponse:
        start_time = asyncio.get_event_loop().time()

        async with session.request(method, url, headers=headers, **kwargs) as response:
            latency = asyncio.get_event_loop().time() - start_time
            logger.info(f"Request to {url} took {latency:.2f} seconds.")

            response_data: Dict[str, Any] = {}
            try:
                response_data = await response.json()
            except aiohttp.ContentTypeError:
                response_data = {}

            if 200 <= response.status < 300:
                message = response_data.get("message", "Request successful")
                data = response_data.get("data", response_data or None)
                return ApiResponse(success=True, message=message, data=data)

            error_message = response_data.get("error") or response_data.get("message") or f"HTTP {response.status}"
            raise DiscopanelAPIError(error_message, response.status)

    async def _make_request(self, method: str, endpoint: str, **kwargs) -> ApiResponse:
        if not self.session:
            raise DiscopanelAPIConnectionError("API session not initialized")

        session = self.session
        auth_token = await self._get_auth_token()
        headers = self._build_request_headers(auth_token, kwargs.pop("headers", None))
        url = f"{self.base_url}{self.api_prefix}{endpoint}"
        logger.debug(f"Making {method} request to {url} with headers {redact_authorization(headers)}")

        try:
            return await asyncio.wait_for(
                self._execute_request(session, method, url, headers, **kwargs),
                timeout=35
            )
        except (asyncio.TimeoutError, aiohttp.ServerTimeoutError) as e:
            logger.error(f"Request timeout: {e}")
            raise DiscopanelAPITimeoutError(f"Request timeout: {str(e)}")
        except aiohttp.ClientError as e:
            logger.error(f"Connection error: {e}")
            raise DiscopanelAPIConnectionError(f"Connection error: {str(e)}")
        except DiscopanelAPIError:
            raise
        except Exception as e:
            logger.error(f"Unexpected error: {e}")
            raise DiscopanelAPIError(f"Unexpected error: {str(e)}")

    def _parse_server_info(self, data: Dict[str, Any]) -> ServerInfo:
        payload = data.get("server", data.get("data", data))
        status_raw = _first(payload, ["status", "server_status", "state"]) or "UNKNOWN"
        name_raw = _first(payload, ["name", "server_name"]) or "Unknown"

        return ServerInfo(
            id=str(_first(payload, ["id", "server_id"]) or ""),
            name=str(name_raw),
            status=str(status_raw).upper(),
            mc_version=_first(payload, ["mc_version", "minecraft_version", "mcVersion"]),
            mod_loader=_first(payload, ["mod_loader", "loader", "modLoader"]),
            players_online=_safe_int(_first(payload, ["players_online", "online_players", "playersOnline", "onlinePlayers", "online"])),
            max_players=_safe_int(_first(payload, ["max_players", "players_max", "maxPlayers"])),
            cpu_percent=_safe_float(_first(payload, ["cpu_percent", "cpu", "cpuPercent"])),
            memory_usage=_safe_int(_first(payload, ["memory_usage", "memoryUsed", "memory_used", "memoryUsage", "mem"])),
            memory=_safe_int(_first(payload, ["memory", "memoryLimit", "memory_limit", "maxMemory"])),
            tps=_safe_float(_first(payload, ["tps"]))
        )

    async def _perform_action(self, endpoint: str, verb: str, server_id: str, payload: Dict[str, Any]) -> ApiResponse:
        try:
            resp = await self._make_request("POST", endpoint, json=payload)
            resp.message = f"Server {server_id} {verb} command sent successfully"
            return resp
        except DiscopanelAPIError as e:
            return ApiResponse(
                success=False,
                message=f"Failed to {verb} server {server_id}: {str(e)}",
                error_code=e.status_code
            )

    async def start_server(self, server_id: str) -> ApiResponse:
        return await self._perform_action(
            "/discopanel.v1.ServerService/StartServer",
            "start",
            server_id,
            {"id": server_id}
        )

    async def stop_server(self, server_id: str) -> ApiResponse:
        return await self._perform_action(
            "/discopanel.v1.ServerService/StopServer",
            "stop",
            server_id,
            {"id": server_id}
        )

    async def restart_server(self, server_id: str) -> ApiResponse:
        return await self._perform_action(
            "/discopanel.v1.ServerService/RestartServer",
            "restart",
            server_id,
            {"id": server_id}
        )

    async def send_command(self, server_id: str, command: str) -> ApiResponse:
        if not command or not command.strip():
            return ApiResponse(success=False, message="Command cannot be empty", error_code=400)

        try:
            resp = await self._make_request(
                "POST",
                "/discopanel.v1.ServerService/SendCommand",
                json={"id": server_id, "command": command}
            )
            resp.message = f"Command '{command}' sent to server {server_id}"
            return resp
        except DiscopanelAPIError as e:
            return ApiResponse(
                success=False,
                message=f"Failed to send command to server {server_id}: {str(e)}",
                error_code=e.status_code
            )

    async def get_server(self, server_id: str) -> ApiResponse:
        try:
            resp = await self._make_request(
                "POST",
                "/discopanel.v1.ServerService/GetServer",
                json={"id": server_id}
            )
            if resp.success and isinstance(resp.data, dict):
                resp.data = self._parse_server_info(resp.data)
                resp.message = f"Server {server_id} information retrieved successfully"
            return resp
        except DiscopanelAPIError as e:
            return ApiResponse(
                success=False,
                message=f"Failed to get server {server_id}: {str(e)}",
                error_code=e.status_code
            )


__all__ = [
    "DiscopanelAPI",
    "DiscopanelAPIError",
    "DiscopanelAPIConnectionError",
    "DiscopanelAPITimeoutError",
    "ServerInfo",
    "ApiResponse",
    "redact_authorization",
]
