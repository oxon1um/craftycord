"""Configuration validation and startup tests for the Discopanel Discord Bot."""

import os
import uuid
import asyncio
import logging
from typing import Dict, List, Optional, Union, Tuple
from dataclasses import dataclass
from datetime import datetime, timezone

from .discopanel_api import DiscopanelAPI, DiscopanelAPIError, ApiResponse
from .token_manager import TokenManager, TokenManagerError


logger = logging.getLogger(__name__)

# Configuration validation constants
REQUIRED_ENV_VARS = ['DISCORD_TOKEN', 'DISCOPANEL_URL', 'SERVER_ID', 'DISCOPANEL_USERNAME', 'DISCOPANEL_PASSWORD']
OPTIONAL_ENV_VARS = ['GUILD_ID']
STARTUP_TEST_TIMEOUT = 20
TOKEN_LIFETIME_BUFFER_HOURS = 2


@dataclass
class ValidationResult:
    """Result of a configuration validation check"""
    success: bool
    message: str
    details: Optional[Dict[str, Union[str, bool, int, float]]] = None
    error_code: Optional[str] = None


@dataclass
class AuthenticationTestResult:
    """Result of authentication testing"""
    success: bool
    auth_method: str
    message: str
    token_info: Optional[Dict[str, Union[str, datetime]]] = None
    response_format_valid: bool = False
    api_latency_ms: Optional[float] = None
    error_details: Optional[str] = None


class ConfigurationValidator:
    """Validates bot configuration and performs pre-flight authentication checks"""
    
    @staticmethod
    def validate_environment_variables() -> ValidationResult:
        """Validate required environment variables are present and valid
        
        Returns:
            ValidationResult with success status and details
        """
        missing_vars = []
        invalid_vars = []
        
        # Check required variables
        for var in REQUIRED_ENV_VARS:
            value = os.getenv(var)
            if not value:
                missing_vars.append(var)
            elif var == 'SERVER_ID':
                # Validate SERVER_ID is a valid UUID
                try:
                    uuid.UUID(value)
                except ValueError:
                    invalid_vars.append(f"{var} (must be valid UUID)")
            # Additional validation for specific variables if they are present
            # (GUILD_ID is now optional, so only validate if present)
        
        if missing_vars or invalid_vars:
            error_message = "Environment variable validation failed"
            details = {}
            if missing_vars:
                details['missing'] = ', '.join(missing_vars)
            if invalid_vars:
                details['invalid'] = ', '.join(invalid_vars)
            
            return ValidationResult(
                success=False,
                message=error_message,
                details=details,
                error_code="INVALID_ENV_VARS"
            )
        
        return ValidationResult(
            success=True,
            message="All required environment variables are valid",
            details={
                'validated_vars': len(REQUIRED_ENV_VARS),
                'server_id': os.getenv('SERVER_ID') or 'unknown',
                'guild_id': os.getenv('GUILD_ID') or 'not_set'
            }
        )
    
    @staticmethod
    def validate_authentication_configuration() -> ValidationResult:
        """Validate Discopanel authentication configuration"""
        discopanel_username = os.getenv('DISCOPANEL_USERNAME')
        discopanel_password = os.getenv('DISCOPANEL_PASSWORD')

        if discopanel_username and discopanel_password:
            return ValidationResult(
                success=True,
                message="Username/password authentication configured",
                details={
                    'auth_method': 'credentials',
                    'username': discopanel_username,
                    'password_length': len(discopanel_password)
                }
            )

        missing_items = []
        if not discopanel_username:
            missing_items.append("DISCOPANEL_USERNAME")
        if not discopanel_password:
            missing_items.append("DISCOPANEL_PASSWORD")

        return ValidationResult(
            success=False,
            message="Invalid Discopanel authentication configuration",
            details={
                'error': "DISCOPANEL_USERNAME and DISCOPANEL_PASSWORD are required",
                'missing': ', '.join(missing_items)
            },
            error_code="INVALID_AUTH_CONFIG"
        )
    
    @staticmethod
    def validate_discord_configuration() -> ValidationResult:
        """Validate Discord bot configuration
        
        Returns:
            ValidationResult for Discord configuration
        """
        discord_token = os.getenv('DISCORD_TOKEN')
        guild_id = os.getenv('GUILD_ID')
        
        if not discord_token:
            return ValidationResult(
                success=False,
                message="DISCORD_TOKEN is required",
                error_code="MISSING_DISCORD_TOKEN"
            )
        
        # Basic token format validation (Discord tokens are typically base64-like)
        if len(discord_token) < 50:
            return ValidationResult(
                success=False,
                message="DISCORD_TOKEN appears to be invalid (too short)",
                error_code="INVALID_DISCORD_TOKEN"
            )
        
        # Only validate GUILD_ID if it's provided (it's optional)
        if guild_id:
            try:
                guild_id_int = int(guild_id)
                if guild_id_int <= 0:
                    return ValidationResult(
                        success=False,
                        message="GUILD_ID must be a positive integer",
                        error_code="INVALID_GUILD_ID"
                    )
            except (ValueError, TypeError):
                return ValidationResult(
                    success=False,
                    message="GUILD_ID must be a valid Discord guild ID",
                    error_code="INVALID_GUILD_ID"
                )
        
        return ValidationResult(
            success=True,
            message="Discord configuration is valid",
            details={
                'token_length': len(discord_token),
                'guild_id': guild_id or 'not_set'
            }
        )


class AuthenticationTester:
    """Tests authentication methods and API connectivity"""
    
    @staticmethod
    @staticmethod
    async def test_credentials_auth(base_url: str, username: str, password: str, server_id: str) -> AuthenticationTestResult:
        """Test username/password authentication with TokenManager"""
        start_time = asyncio.get_event_loop().time()
        token_manager = None
        
        try:
            # Initialize TokenManager
            token_manager = TokenManager(base_url, username, password)
            
            async with DiscopanelAPI(base_url, token_manager) as api:
                async with asyncio.timeout(STARTUP_TEST_TIMEOUT):
                    response = await api.get_server(server_id)
                    
                end_time = asyncio.get_event_loop().time()
                latency = (end_time - start_time) * 1000  # Convert to milliseconds
                
                # Get token information
                token_info = {
                    'method': 'credentials',
                    'validated_at': datetime.now(timezone.utc),
                    'has_token': token_manager.has_token,
                    'expires_at': token_manager.token_expires_at
                }
                
                if response.success:
                    return AuthenticationTestResult(
                        success=True,
                        auth_method="credentials",
                        message="Username/password authentication successful",
                        token_info=token_info,
                        response_format_valid=True,
                        api_latency_ms=latency
                    )
                else:
                    return AuthenticationTestResult(
                        success=False,
                        auth_method="credentials",
                        message=f"API request failed: {response.message}",
                        token_info=token_info,
                        response_format_valid=False,
                        api_latency_ms=latency,
                        error_details=response.message
                    )
                    
        except asyncio.TimeoutError:
            return AuthenticationTestResult(
                success=False,
                auth_method="credentials",
                message="Authentication test timed out",
                error_details=f"Request exceeded {STARTUP_TEST_TIMEOUT}s timeout"
            )
        except TokenManagerError as e:
            return AuthenticationTestResult(
                success=False,
                auth_method="credentials",
                message=f"TokenManager authentication failed: {str(e)}",
                error_details=str(e)
            )
        except DiscopanelAPIError as e:
            return AuthenticationTestResult(
                success=False,
                auth_method="credentials",
                message=f"API authentication failed: {str(e)}",
                error_details=str(e)
            )
        except Exception as e:
            return AuthenticationTestResult(
                success=False,
                auth_method="credentials",
                message=f"Unexpected error during authentication test: {str(e)}",
                error_details=str(e)
            )
        finally:
            # Clean up TokenManager
            if token_manager:
                try:
                    await token_manager.close()
                except Exception as cleanup_error:
                    logger.warning(f"Error cleaning up TokenManager during test: {cleanup_error}")
    
    @staticmethod
    async def validate_response_format(response: ApiResponse) -> bool:
        """Validate API response format is as expected
        
        Args:
            response: API response to validate
            
        Returns:
            True if response format is valid, False otherwise
        """
        try:
            # Check basic response structure
            if not hasattr(response, 'success') or not hasattr(response, 'message'):
                logger.error("Response missing required success/message fields")
                return False
            
            if not isinstance(response.success, bool):
                logger.error("Response success field is not boolean")
                return False
            
            if not isinstance(response.message, str):
                logger.error("Response message field is not string")
                return False
            
            # If response has data, validate it
            if hasattr(response, 'data') and response.data is not None:
                if not isinstance(response.data, (dict, object)):
                    logger.error("Response data field has unexpected type")
                    return False
            
            return True
            
        except Exception as e:
            logger.error(f"Error validating response format: {e}")
            return False
    
    @staticmethod
    def validate_token_lifetime(token_expires_at: Optional[datetime]) -> ValidationResult:
        """Validate token has sufficient lifetime remaining
        
        Args:
            token_expires_at: Token expiration timestamp (None for static tokens)
            
        Returns:
            ValidationResult for token lifetime validation
        """
        if token_expires_at is None:
            return ValidationResult(
                success=True,
                message="Static token - no expiration validation needed",
                details={'token_type': 'static'}
            )
        
        current_time = datetime.now(timezone.utc)
        time_remaining = token_expires_at - current_time
        hours_remaining = time_remaining.total_seconds() / 3600
        
        if hours_remaining < TOKEN_LIFETIME_BUFFER_HOURS:
            return ValidationResult(
                success=False,
                message=f"Token expires too soon (in {hours_remaining:.1f} hours)",
                details={
                    'expires_at': token_expires_at.isoformat(),
                    'hours_remaining': hours_remaining,
                    'minimum_required': TOKEN_LIFETIME_BUFFER_HOURS
                },
                error_code="TOKEN_EXPIRES_SOON"
            )
        
        return ValidationResult(
            success=True,
            message=f"Token has sufficient lifetime ({hours_remaining:.1f} hours remaining)",
            details={
                'expires_at': token_expires_at.isoformat(),
                'hours_remaining': hours_remaining
            }
        )


def _validate_environment(validator: ConfigurationValidator) -> Tuple[bool, List[ValidationResult]]:
    """Validate environment variables step"""
    results = []
    
    env_result = validator.validate_environment_variables()
    results.append(env_result)
    
    if not env_result.success:
        logger.error(f"Environment validation failed: {env_result.message}")
        return False, results
    
    return True, results


def _validate_discord_config(validator: ConfigurationValidator) -> Tuple[bool, List[ValidationResult]]:
    """Validate Discord configuration step"""
    results = []
    
    discord_result = validator.validate_discord_configuration()
    results.append(discord_result)
    
    if not discord_result.success:
        logger.error(f"Discord configuration validation failed: {discord_result.message}")
        return False, results
    
    return True, results


def _validate_auth_config(validator: ConfigurationValidator) -> Tuple[bool, ValidationResult]:
    """Validate authentication configuration step"""
    auth_config_result = validator.validate_authentication_configuration()
    
    if not auth_config_result.success:
        logger.error(f"Authentication configuration validation failed: {auth_config_result.message}")
        return False, auth_config_result
    
    return True, auth_config_result


async def _perform_auth_test(auth_config_result: ValidationResult, tester: AuthenticationTester) -> Optional[AuthenticationTestResult]:
    """Perform authentication testing step"""
    discopanel_url = os.getenv('DISCOPANEL_URL')
    server_id = os.getenv('SERVER_ID')
    discopanel_username = os.getenv('DISCOPANEL_USERNAME')
    discopanel_password = os.getenv('DISCOPANEL_PASSWORD')
    
    if not auth_config_result.details:
        logger.error("Auth config result is missing details")
        return None
        
    logger.info(f"Testing authentication using method: {auth_config_result.details.get('auth_method', 'unknown')}")
    
    if not discopanel_url or not discopanel_username or not discopanel_password or not server_id:
        logger.error("Missing required configuration for credentials auth")
        return None
    return await tester.test_credentials_auth(discopanel_url, discopanel_username, discopanel_password, server_id)


def _validate_token_lifetime_step(auth_test_result: AuthenticationTestResult, 
                                  tester: AuthenticationTester, 
                                  validation_results: List[ValidationResult]) -> None:
    """Validate token lifetime for dynamic tokens
    
    Args:
        auth_test_result: The authentication test result
        tester: The authentication tester instance
        validation_results: List to append validation results to
    """
    if not auth_test_result.token_info or not auth_test_result.token_info.get('expires_at'):
        return
    
    expires_at = auth_test_result.token_info.get('expires_at')
    if isinstance(expires_at, datetime):
        lifetime_result = tester.validate_token_lifetime(expires_at)
        validation_results.append(lifetime_result)
        
        if not lifetime_result.success:
            logger.warning(f"Token lifetime validation failed: {lifetime_result.message}")
            # Don't fail startup for token lifetime warnings, but log it
    else:
        logger.warning(f"Invalid expiration format: {type(expires_at)} - {expires_at}")


async def perform_comprehensive_startup_validation() -> Tuple[bool, List[ValidationResult], Optional[AuthenticationTestResult]]:
    """Perform comprehensive startup validation and testing
    
    Returns:
        Tuple of (overall_success, validation_results, auth_test_result)
    """
    validator = ConfigurationValidator()
    tester = AuthenticationTester()
    validation_results: List[ValidationResult] = []
    
    logger.info("Starting comprehensive configuration validation...")
    
    # Step 1: Validate environment variables
    env_success, env_results = _validate_environment(validator)
    validation_results.extend(env_results)
    if not env_success:
        return False, validation_results, None
    
    # Step 2: Validate Discord configuration
    discord_success, discord_results = _validate_discord_config(validator)
    validation_results.extend(discord_results)
    if not discord_success:
        return False, validation_results, None
    
    # Step 3: Validate authentication configuration
    auth_success, auth_config_result = _validate_auth_config(validator)
    validation_results.append(auth_config_result)
    if not auth_success:
        return False, validation_results, None
    
    # Step 4: Test authentication
    auth_test_result = await _perform_auth_test(auth_config_result, tester)
    if not auth_test_result or not auth_test_result.success:
        if auth_test_result:
            logger.error(f"Authentication test failed: {auth_test_result.message}")
        return False, validation_results, auth_test_result
    
    # Step 5: Validate token lifetime (for dynamic tokens)
    _validate_token_lifetime_step(auth_test_result, tester, validation_results)
    
    logger.info(f"Authentication test successful - latency: {auth_test_result.api_latency_ms:.1f}ms")
    return True, validation_results, auth_test_result

def _log_success(auth_result: Optional[AuthenticationTestResult]) -> None:
    """Log success details for startup health check."""
    logger.info("✅ All startup validation checks passed")
    if auth_result and auth_result.api_latency_ms:
        logger.info(f"   - API latency: {auth_result.api_latency_ms:.1f}ms")
    if auth_result and auth_result.token_info:
        expires_at = auth_result.token_info.get('expires_at')
        if expires_at:
            logger.info(f"   - Token expires: {expires_at}")


async def perform_startup_health_check() -> bool:
    """Perform a quick startup health check

    Returns:
        True if all checks pass, False otherwise
    """
    try:
        success, results, auth_result = await perform_comprehensive_startup_validation()

        if success:
            _log_success(auth_result)
        else:
            logger.error("❌ Startup validation failed")
            for result in results:
                if not result.success:
                    logger.error(f"   - {result.message}")
                    if result.error_code:
                        logger.error(f"     Error code: {result.error_code}")

        return success

    except Exception as e:
        logger.error(f"Startup health check failed with unexpected error: {e}")
        return False


# Export public classes and functions
__all__ = [
    'ConfigurationValidator',
    'AuthenticationTester',
    'ValidationResult',
    'AuthenticationTestResult',
    'perform_comprehensive_startup_validation',
    'perform_startup_health_check'
]
