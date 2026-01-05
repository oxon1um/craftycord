"""
Monitoring utilities for error tracking and observability.

This module provides optional integration with Sentry for error tracking
and structured logging utilities for better observability.
"""

import os
import logging
from typing import Optional, Dict, Any, Literal
from functools import wraps

logger = logging.getLogger(__name__)

# Global variables to track monitoring state
_sentry_initialized = False
_sentry_available = False

def initialize_sentry() -> bool:
    """
    Initialize Sentry error tracking if configured.
    
    Returns:
        bool: True if Sentry was successfully initialized, False otherwise
    """
    global _sentry_initialized, _sentry_available
    
    if _sentry_initialized:
        return _sentry_available
    
    sentry_dsn = os.getenv('SENTRY_DSN')
    if not sentry_dsn:
        logger.info("SENTRY_DSN not configured - Sentry error tracking disabled")
        _sentry_initialized = True
        _sentry_available = False
        return False
    
    try:
        import sentry_sdk
        from sentry_sdk.integrations.logging import LoggingIntegration
        from sentry_sdk.integrations.asyncio import AsyncioIntegration
        
        # Configure Sentry with appropriate integrations
        sentry_logging = LoggingIntegration(
            level=logging.INFO,        # Capture info and above as breadcrumbs
            event_level=logging.ERROR  # Send errors as events
        )
        
        sentry_sdk.init(
            dsn=sentry_dsn,
            integrations=[
                sentry_logging,
                AsyncioIntegration()
            ],
            traces_sample_rate=float(os.getenv('SENTRY_TRACES_SAMPLE_RATE', '0.1')),
            environment=os.getenv('ENVIRONMENT', 'development'),
            release=os.getenv('RELEASE_VERSION', 'unknown'),
            # Additional context
            before_send=_before_send_filter,
        )
        
        logger.info("Sentry error tracking initialized successfully")
        _sentry_initialized = True
        _sentry_available = True
        return True
        
    except ImportError:
        logger.warning("Sentry SDK not installed - install with: pip install sentry-sdk")
        _sentry_initialized = True
        _sentry_available = False
        return False
    except Exception as e:
        logger.error(f"Failed to initialize Sentry: {e}")
        _sentry_initialized = True
        _sentry_available = False
        return False

def _before_send_filter(event, hint):
    """
    Filter Sentry events before sending to avoid noise.
    
    Args:
        event: The Sentry event data
        hint: Additional context about the event
        
    Returns:
        The event if it should be sent, None if it should be filtered out
    """
    # Filter out common Discord.py connection errors that aren't actionable
    if 'exception' in event:
        for exception in event['exception']['values']:
            exc_type = exception.get('type', '')
            exc_value = exception.get('value', '')
            
            # Skip common network/connection errors
            if any(error_type in exc_type for error_type in [
                'ConnectionError', 'TimeoutError', 'HTTPException', 
                'ClientConnectorError', 'ServerDisconnectedError'
            ]):
                logger.debug(f"Filtering out common network error: {exc_type}: {exc_value}")
                return None
                
            # Skip Discord rate limit errors (these are handled gracefully)
            if 'RateLimited' in exc_type or 'rate limit' in exc_value.lower():
                logger.debug(f"Filtering out rate limit error: {exc_type}: {exc_value}")
                return None
    
    return event

def capture_exception(error: Exception, context: Optional[Dict[str, Any]] = None) -> None:
    """
    Capture an exception for error tracking.
    
    Args:
        error: The exception to capture
        context: Additional context to include with the error
    """
    if not _sentry_available:
        return
        
    try:
        import sentry_sdk
        
        # Add context if provided
        if context:
            with sentry_sdk.configure_scope() as scope:
                for key, value in context.items():
                    scope.set_tag(key, value)
        
        sentry_sdk.capture_exception(error)
        logger.debug(f"Exception captured by Sentry: {type(error).__name__}: {error}")
        
    except Exception as e:
        logger.error(f"Failed to capture exception in Sentry: {e}")

def capture_message(message: str, level: Literal["fatal", "critical", "error", "warning", "info", "debug"] = "info", context: Optional[Dict[str, Any]] = None) -> None:
    """
    Capture a message for monitoring.
    
    Args:
        message: The message to capture
        level: The severity level (info, warning, error)
        context: Additional context to include
    """
    if not _sentry_available:
        return
        
    try:
        import sentry_sdk
        
        # Add context if provided
        if context:
            with sentry_sdk.configure_scope() as scope:
                for key, value in context.items():
                    scope.set_tag(key, value)
        
        sentry_sdk.capture_message(message, level)
        logger.debug(f"Message captured by Sentry: {message}")
        
    except Exception as e:
        logger.error(f"Failed to capture message in Sentry: {e}")

def monitor_errors(func):
    """
    Decorator to automatically capture exceptions from functions.
    
    Args:
        func: The function to monitor
        
    Returns:
        The wrapped function
    """
    @wraps(func)
    async def async_wrapper(*args, **kwargs):
        try:
            return await func(*args, **kwargs)
        except Exception as e:
            capture_exception(e, {
                'function': func.__name__,
                'module': func.__module__,
            })
            raise
    
    @wraps(func)
    def sync_wrapper(*args, **kwargs):
        try:
            return func(*args, **kwargs)
        except Exception as e:
            capture_exception(e, {
                'function': func.__name__,
                'module': func.__module__,
            })
            raise
    
    # Return appropriate wrapper based on function type
    import asyncio
    if asyncio.iscoroutinefunction(func):
        return async_wrapper
    else:
        return sync_wrapper

def add_breadcrumb(message: str, category: str = "default", level: str = "info", data: Optional[Dict[str, Any]] = None) -> None:
    """
    Add a breadcrumb for debugging context.
    
    Args:
        message: The breadcrumb message
        category: The category of the breadcrumb
        level: The severity level
        data: Additional data to include
    """
    if not _sentry_available:
        return
        
    try:
        import sentry_sdk
        
        sentry_sdk.add_breadcrumb(
            message=message,
            category=category,
            level=level,
            data=data or {}
        )
        
    except Exception as e:
        logger.error(f"Failed to add breadcrumb in Sentry: {e}")

def get_monitoring_status() -> Dict[str, Any]:
    """
    Get the current monitoring status.
    
    Returns:
        Dict with monitoring configuration status
    """
    return {
        'sentry_initialized': _sentry_initialized,
        'sentry_available': _sentry_available,
        'sentry_dsn_configured': bool(os.getenv('SENTRY_DSN')),
        'environment': os.getenv('ENVIRONMENT', 'development'),
        'release': os.getenv('RELEASE_VERSION', 'unknown'),
    }
