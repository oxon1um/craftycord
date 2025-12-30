"""Token management for Discopanel API authentication."""

import aiohttp
import asyncio
import logging
import random
import json
import stat
import uuid
from pathlib import Path
from typing import Any, Optional
from datetime import datetime, timezone, timedelta

logger = logging.getLogger(__name__)


class TokenManagerError(Exception):
    """Base exception for token manager errors"""
    def __init__(self, message: str, status_code: Optional[int] = None):
        super().__init__(message)
        self.status_code = status_code


class TokenManagerAuthError(TokenManagerError):
    """Exception raised when authentication fails"""
    pass


class TokenManagerConnectionError(TokenManagerError):
    """Exception raised when connection to API fails"""
    pass


class TokenManager:
    """Thread-safe token manager for Discopanel authentication."""

    BASE_LOGIN_ENDPOINT = "/discopanel.v1.AuthService/Login"
    REFRESH_BUFFER_HOURS = 4
    MAX_RETRY_ATTEMPTS = 3
    INITIAL_RETRY_DELAY = 1.0
    MAX_RETRY_DELAY = 60.0
    CACHE_FILE_NAME = "~/.discopanel_token_cache.json"
    
    @staticmethod
    def _generate_correlation_id() -> str:
        """Generate a unique correlation ID for tracking operations
        
        Returns:
            A unique correlation ID string
        """
        return str(uuid.uuid4())[:8]
    
    @staticmethod
    def _redact_credentials(username: str, password: str) -> dict:
        """Redact sensitive credential information for logging
        
        Args:
            username: The username to redact
            password: The password to redact
            
        Returns:
            Dictionary with redacted credential information safe for logging
        """
        return {
            'username': f"{username[:2]}***{username[-2:]}" if len(username) > 4 else "***",
            'password_length': len(password)
        }
    
    def __init__(self, base_url: str, username: str, password: str) -> None:
        self.base_url = base_url.rstrip('/')
        self.username = username
        self.password = password
        
        # Cache file path
        self._cache_path = Path(self.CACHE_FILE_NAME).expanduser()
        
        # Token storage (protected by lock)
        self._token: Optional[str] = None
        self._token_expires_at: Optional[datetime] = None
        
        # Proactive refresh state
        self._refresh_task: Optional[asyncio.Task] = None
        self._refresh_cancelled = False
        
        # Thread-safe access guard
        self._lock = asyncio.Lock()
        
        # Load cached token on initialization
        self._load_cached_token()
    
    async def login(self) -> str:
        """Perform login to obtain authentication token
        
        Calls POST /api/v2/auth/login with username/password credentials,
        parses the response to extract the token and expiration timestamp,
        and stores them in memory.
        
        Returns:
            The authentication token
            
        Raises:
            TokenManagerAuthError: If authentication fails
            TokenManagerConnectionError: If connection fails
        """
        async with self._lock:
            return await self._perform_login()
    
    def _parse_token_expiration(self, expires: Any) -> Optional[datetime]:
        """Parse token expiration timestamp from various formats
        
        Args:
            expires: The expiration value from the API response
            
        Returns:
            Parsed datetime or None if parsing fails
        """
        if not expires:
            return None
            
        try:
            if isinstance(expires, str):
                return datetime.fromisoformat(expires.replace('Z', '+00:00'))
            elif isinstance(expires, (int, float)):
                return datetime.fromtimestamp(expires, tz=timezone.utc)
            else:
                logger.warning(f"Unexpected expiration format: {expires}")
                return None
        except (ValueError, TypeError) as e:
            logger.warning(f"Failed to parse token expiration: {e}")
            return None
    
    def _process_login_response_data(self, response_data: dict, correlation_id: str) -> str:
        """Process successful login response data."""
        candidates = []
        if isinstance(response_data, dict):
            candidates.append(response_data)
            if isinstance(response_data.get('data'), dict):
                candidates.append(response_data['data'])

        token = None
        expires = None
        for candidate in candidates:
            token = candidate.get('token') or candidate.get('access_token')
            expires = candidate.get('expires') or candidate.get('expires_at')
            if token:
                break

        if not token:
            raise TokenManagerAuthError("Token not found in login response")

        self._token_expires_at = self._parse_token_expiration(expires)
        self._token = token
        self._save_token_to_cache(correlation_id)
        self._schedule_refresh_task()

        redacted_creds = self._redact_credentials(self.username, self.password)
        logger.info(f"[{correlation_id}] Authentication successful - user: {redacted_creds['username']}, expires: {self._token_expires_at or 'unknown'}")
        logger.debug(f"[{correlation_id}] Token length: {len(token)}, timestamp: {datetime.now(timezone.utc)}")

        return token
    
    async def _handle_login_request(self, session: aiohttp.ClientSession, url: str, 
                                   login_data: dict, headers: dict, correlation_id: str) -> str:
        """Handle the actual login HTTP request
        
        Args:
            session: The aiohttp client session
            url: The login URL
            login_data: The login payload
            headers: Request headers
            correlation_id: Correlation ID for logging
            
        Returns:
            The authentication token
            
        Raises:
            TokenManagerAuthError: If authentication fails
        """
        async with session.post(url, json=login_data, headers=headers) as response:
            response_data: dict = {}
            try:
                response_data = await response.json()
            except Exception:
                response_data = {}

            if response.status == 200:
                try:
                    return self._process_login_response_data(response_data, correlation_id)
                except TokenManagerError as token_error:
                    logger.debug(f"[{correlation_id}] Could not parse token from login response: {token_error}")

            error_message = (
                response_data.get('error')
                or response_data.get('message')
                or response_data.get('detail')
                or f"HTTP {response.status}: {response.reason}"
            )
            redacted_creds = self._redact_credentials(self.username, self.password)
            logger.error(f"[{correlation_id}] Authentication failed - user: {redacted_creds['username']}, status: {response.status}, error: {error_message}")
            raise TokenManagerAuthError(f"Login failed: {error_message}", response.status)
    
    async def _perform_login(self) -> str:
        """Internal method to perform the actual login request
        
        This method is called while holding the lock to ensure thread safety.
        
        Returns:
            The authentication token
            
        Raises:
            TokenManagerAuthError: If authentication fails
            TokenManagerConnectionError: If connection fails
        """
        # Generate correlation ID for this authentication attempt
        correlation_id = self._generate_correlation_id()
        redacted_creds = self._redact_credentials(self.username, self.password)
        
        login_data = {
            "username": self.username,
            "password": self.password
        }
        
        url = f"{self.base_url}{self.BASE_LOGIN_ENDPOINT}"
        headers = {"Content-Type": "application/json"}
        
        logger.info(f"[{correlation_id}] Starting authentication attempt - user: {redacted_creds['username']}, url: {url}")
        logger.debug(f"[{correlation_id}] Authentication context - password_length: {redacted_creds['password_length']}")
        
        connector = aiohttp.TCPConnector(limit=10, ssl=False)
        timeout = aiohttp.ClientTimeout(total=30, sock_connect=5, sock_read=20)
        
        try:
            async with aiohttp.ClientSession(connector=connector, timeout=timeout) as session:
                return await self._handle_login_request(session, url, login_data, headers, correlation_id)
        
        except aiohttp.ClientError as e:
            logger.error(f"[{correlation_id}] Authentication connection error - user: {redacted_creds['username']}, error: {str(e)}")
            raise TokenManagerConnectionError(f"Login connection error: {str(e)}")
        except TokenManagerError:
            # Re-raise our custom exceptions
            raise
        except Exception as e:
            logger.error(f"[{correlation_id}] Authentication unexpected error - user: {redacted_creds['username']}, error: {str(e)}")
            raise TokenManagerError(f"Unexpected login error: {str(e)}")
    
    async def get_token(self) -> str:
        """Get a valid authentication token with proactive refresh
        
        Returns the current token if it's valid, or performs a new login
        if the token is expired or doesn't exist. Triggers proactive refresh
        if token is close to expiry.
        
        Returns:
            A valid authentication token
            
        Raises:
            TokenManagerError: If unable to obtain a valid token
        """
        async with self._lock:
            if self._is_token_valid():
                # Check if we need proactive refresh
                if self._needs_proactive_refresh():
                    logger.debug("Token approaching expiry, performing proactive refresh")
                    return await self._perform_login()
                return self._token  # type: ignore
            
            # Token is invalid or doesn't exist, perform login
            return await self._perform_login()
    
    async def get_valid_token(self) -> str:
        """Get a valid authentication token
        
        Returns the current token if it's valid, or performs a new login
        if the token is expired or doesn't exist.
        
        Returns:
            A valid authentication token
            
        Raises:
            TokenManagerError: If unable to obtain a valid token
        """
        async with self._lock:
            if self._is_token_valid():
                return self._token  # type: ignore
            
            # Token is invalid or doesn't exist, perform login
            return await self._perform_login()
    
    def _is_token_valid(self) -> bool:
        """Check if the current token is valid
        
        A token is considered valid if:
        - It exists
        - It hasn't expired (if expiration is known)
        
        Returns:
            True if token is valid, False otherwise
        """
        if not self._token:
            return False
        
        if self._token_expires_at:
            current_time = datetime.now(timezone.utc)
            if current_time >= self._token_expires_at:
                logger.debug("Token has expired")
                return False
        
        return True
    
    def _needs_proactive_refresh(self) -> bool:
        """Check if token needs proactive refresh
        
        Returns True if token is within REFRESH_BUFFER_HOURS of expiring
        """
        if not self._token or not self._token_expires_at:
            return False
            
        current_time = datetime.now(timezone.utc)
        refresh_threshold = self._token_expires_at - timedelta(hours=self.REFRESH_BUFFER_HOURS)
        return current_time >= refresh_threshold
    
    def _schedule_refresh_task(self) -> None:
        """Schedule a background task to refresh token before expiration"""
        # Cancel existing refresh task
        if self._refresh_task and not self._refresh_task.done():
            self._refresh_task.cancel()
        
        if not self._token_expires_at:
            logger.debug("No token expiration available, skipping background refresh")
            return
        
        # Calculate sleep time until refresh is needed
        current_time = datetime.now(timezone.utc)
        refresh_at = self._token_expires_at - timedelta(hours=self.REFRESH_BUFFER_HOURS)
        sleep_seconds = (refresh_at - current_time).total_seconds()
        
        if sleep_seconds <= 0:
            logger.debug("Token already needs refresh, skipping background task")
            return
        
        logger.debug(f"Scheduling token refresh in {sleep_seconds:.1f} seconds")
        self._refresh_task = asyncio.create_task(self._background_refresh(sleep_seconds))
    
    async def _background_refresh(self, sleep_seconds: float) -> None:
        """Background task that refreshes token before expiration"""
        try:
            await asyncio.sleep(sleep_seconds)
            
            # Check if we should still refresh (token might have been updated)
            async with self._lock:
                if self._refresh_cancelled or not self._needs_proactive_refresh():
                    logger.debug("Background refresh cancelled or no longer needed")
                    return
                
                logger.info("Performing background token refresh")
                await self._perform_login_with_retry()
                logger.info("Background token refresh completed successfully")
                
        except asyncio.CancelledError:
            logger.debug("Background refresh task cancelled")
            raise
        except Exception as e:
            logger.error(f"Background refresh failed: {e}")
    
    async def _perform_login_with_retry(self) -> str:
        """Perform login with exponential backoff retry logic
        
        Returns:
            The authentication token
            
        Raises:
            TokenManagerError: If all retry attempts fail
        """
        for attempt in range(self.MAX_RETRY_ATTEMPTS):
            try:
                return await self._perform_login()
            except TokenManagerError as e:
                if attempt == self.MAX_RETRY_ATTEMPTS - 1:
                    logger.error(f"Login failed after {self.MAX_RETRY_ATTEMPTS} attempts: {e}")
                    raise
                
                # Calculate exponential backoff delay with jitter
                delay = min(
                    self.INITIAL_RETRY_DELAY * (2 ** attempt) + random.uniform(0, 1),
                    self.MAX_RETRY_DELAY
                )
                
                logger.warning(f"Login attempt {attempt + 1} failed: {e}. Retrying in {delay:.1f}s")
                await asyncio.sleep(delay)
        
        # This should never be reached due to the raise in the loop
        raise TokenManagerError("Unexpected error in retry logic")
    
    async def clear_token(self) -> None:
        """Clear the stored token
        
        This method is useful for forcing a re-login on the next token request.
        """
        async with self._lock:
            self._token = None
            self._token_expires_at = None
            
            # Cancel any background refresh task
            if self._refresh_task and not self._refresh_task.done():
                self._refresh_task.cancel()
                self._refresh_task = None
            
            # Remove cache file if it exists
            try:
                if self._cache_path.exists():
                    self._cache_path.unlink()
                    logger.debug(f"Deleted token cache file: {self._cache_path}")
            except OSError as e:
                logger.warning(f"Failed to delete token cache file: {e}")
            
            logger.debug("Token cleared")
    
    @property
    def has_token(self) -> bool:
        """Check if a token is currently stored
        
        Returns:
            True if a token exists (regardless of validity), False otherwise
        """
        return self._token is not None
    
    @property
    def token_expires_at(self) -> Optional[datetime]:
        """Get the token expiration timestamp
        
        Returns:
            The expiration timestamp if known, None otherwise
        """
        return self._token_expires_at
    
    async def close(self) -> None:
        """Clean up resources and cancel background tasks
        
        Call this method when the TokenManager is no longer needed
        to ensure proper cleanup of background tasks.
        """
        async with self._lock:
            # Cancel refresh task
            if self._refresh_task and not self._refresh_task.done():
                self._refresh_task.cancel()
                try:
                    await self._refresh_task
                except asyncio.CancelledError:
                    logger.debug("Refresh task cancellation completed")
                    raise
            
            self._refresh_task = None
            self._refresh_cancelled = True
            logger.debug("TokenManager closed and resources cleaned up")
    
    def _load_cached_token(self) -> None:
        """Load token from cache file if it exists and is valid
        
        This method is called during initialization to restore a previously
        cached token. If the cache is missing, corrupted, or expired, it's
        silently ignored.
        """
        cache_correlation_id = self._generate_correlation_id()
        
        try:
            if not self._cache_path.exists():
                logger.debug(f"[{cache_correlation_id}] Cache load attempt - no cache file found at: {self._cache_path}")
                return
            
            # Check file permissions for security
            file_stat = self._cache_path.stat()
            if file_stat.st_mode & (stat.S_IRGRP | stat.S_IROTH | stat.S_IWGRP | stat.S_IWOTH):
                logger.warning(f"[{cache_correlation_id}] Cache load failed - insecure permissions on: {self._cache_path}")
                return
            
            logger.debug(f"[{cache_correlation_id}] Loading token from cache file: {self._cache_path}")
            
            with open(self._cache_path, 'r') as f:
                cache_data = json.load(f)
            
            # Validate cache structure
            if not isinstance(cache_data, dict):
                logger.warning(f"[{cache_correlation_id}] Cache load failed - invalid format in: {self._cache_path}")
                return
            
            token = cache_data.get('token')
            expires_str = cache_data.get('expires_at')
            cached_at_str = cache_data.get('cached_at')
            
            if not token:
                logger.debug(f"[{cache_correlation_id}] Cache load failed - no token in cache file: {self._cache_path}")
                return
            
            # Parse expiration timestamp if available
            expires_at = None
            if expires_str:
                try:
                    expires_at = datetime.fromisoformat(expires_str)
                    # Validate expiration
                    current_time = datetime.now(timezone.utc)
                    if current_time >= expires_at:
                        logger.debug(f"[{cache_correlation_id}] Cache load ignored - token expired (expires: {expires_at})")
                        return
                except (ValueError, TypeError) as e:
                    logger.warning(f"[{cache_correlation_id}] Cache load failed - invalid expiration format: {e}")
                    return
            
            # Token is valid, restore it
            self._token = token
            self._token_expires_at = expires_at
            
            logger.info(f"[{cache_correlation_id}] Cache load successful - path: {self._cache_path}, expires: {expires_at or 'unknown'}, cached: {cached_at_str or 'unknown'}")
            logger.debug(f"[{cache_correlation_id}] Cached token length: {len(token)}")
            
        except (OSError, json.JSONDecodeError) as e:
            logger.warning(f"[{cache_correlation_id}] Cache load failed - file error: {e}, path: {self._cache_path}")
        except Exception as e:
            logger.error(f"[{cache_correlation_id}] Cache load failed - unexpected error: {e}, path: {self._cache_path}")
    
    def _save_token_to_cache(self, correlation_id: Optional[str] = None) -> None:
        """Save current token to cache file with secure permissions
        
        Args:
            correlation_id: Optional correlation ID for logging context
        
        This method saves the current token and expiration to a JSON file
        with owner-only read/write permissions (mode 0600).
        """
        if correlation_id is None:
            correlation_id = self._generate_correlation_id()
            
        if not self._token:
            logger.debug(f"[{correlation_id}] Cache save skipped - no token to save")
            return
        
        try:
            logger.debug(f"[{correlation_id}] Saving token to cache file: {self._cache_path}")
            
            # Prepare cache data
            cached_at = datetime.now(timezone.utc)
            cache_data = {
                'token': self._token,
                'expires_at': self._token_expires_at.isoformat() if self._token_expires_at else None,
                'cached_at': cached_at.isoformat()
            }
            
            # Create parent directory if it doesn't exist
            self._cache_path.parent.mkdir(parents=True, exist_ok=True)
            
            # Write to temporary file first, then rename for atomic operation
            temp_path = self._cache_path.with_suffix('.tmp')
            with open(temp_path, 'w') as f:
                json.dump(cache_data, f, indent=2)
            
            # Set secure permissions (owner read/write only)
            temp_path.chmod(stat.S_IRUSR | stat.S_IWUSR)
            
            # Atomic rename
            temp_path.rename(self._cache_path)
            
            logger.info(f"[{correlation_id}] Cache save successful - path: {self._cache_path}, expires: {self._token_expires_at or 'unknown'}, cached: {cached_at.isoformat()}")
            logger.debug(f"[{correlation_id}] Cached token length: {len(self._token)}, temp_path: {temp_path}")
            
        except OSError as e:
            logger.warning(f"[{correlation_id}] Cache save failed - file error: {e}, path: {self._cache_path}")
        except Exception as e:
            logger.error(f"[{correlation_id}] Cache save failed - unexpected error: {e}, path: {self._cache_path}")
    
    def __del__(self):
        """Destructor that warns if cleanup wasn't called properly"""
        if self._refresh_task and not self._refresh_task.done():
            logger.warning("TokenManager destroyed without calling close() - background task may leak")


# Export public classes
__all__ = [
    'TokenManager',
    'TokenManagerError',
    'TokenManagerAuthError',
    'TokenManagerConnectionError'
]
