"""
Discord utility functions for safe interaction handling and response management.

This module provides helper functions to handle Discord interactions safely,
including checking if interactions are still valid and sending responses
without triggering errors when interactions have expired.
"""

import logging
import discord
from typing import Optional, Dict, Any

logger = logging.getLogger(__name__)

def can_respond(interaction: discord.Interaction) -> bool:
    """
    Check if an interaction can still receive responses.
    
    Args:
        interaction: The Discord interaction to check
        
    Returns:
        bool: True if the interaction is not expired and has not been responded to.
    """
    return not interaction.is_expired() and not interaction.response.is_done()

def _log_interaction_warning(message: str, interaction: discord.Interaction, error: Optional[Exception] = None, **kwargs):
    """Helper to log warnings about interactions."""
    extra = {
        "interaction_id": interaction.id,
        "interaction_type": interaction.type.name if interaction.type else "unknown",
        "user_id": interaction.user.id if interaction.user else None,
        "guild_id": interaction.guild.id if interaction.guild else None,
        "channel_id": interaction.channel.id if interaction.channel else None,
        "command_name": getattr(interaction.command, 'name', None) if hasattr(interaction, 'command') else None,
        **kwargs
    }
    if error:
        extra['error_type'] = type(error).__name__
        extra['error_message'] = str(error)
        if isinstance(error, discord.HTTPException):
            extra['error_code'] = getattr(error, 'code', None)

    logger.warning(message, extra=extra)


async def safe_respond_async(interaction: discord.Interaction, content: Optional[str] = None, 
                            embed: Optional[discord.Embed] = None, ephemeral: bool = False) -> bool:
    """
    Safely send a response to a Discord interaction without raising exceptions (async version).
    It will attempt an initial response, and if that fails, it will try a followup.
    
    Args:
        interaction: The Discord interaction to respond to
        content: Optional text content for the response
        embed: Optional embed for the response
        ephemeral: Whether the response should be ephemeral (only visible to the user)
        
    Returns:
        bool: True if the response was sent successfully, False otherwise
    """
    if not can_respond(interaction):
        _log_interaction_warning("Skipping response to expired interaction", interaction, skip_reason="interaction_expired")
        return False

    return await _send_response(interaction, content, embed, ephemeral)

def build_kwargs(content: Optional[str], embed: Optional[discord.Embed], ephemeral: bool) -> Dict[str, Any]:
    """
    Build the kwargs dictionary for send_message and followup.send methods.
    """
    kwargs: Dict[str, Any] = {"ephemeral": ephemeral}
    if content is not None:
        kwargs["content"] = content
    if embed is not None:
        kwargs["embed"] = embed
    return kwargs

async def _send_response(interaction: discord.Interaction, content: Optional[str], 
                         embed: Optional[discord.Embed], ephemeral: bool) -> bool:
    """
    Internal function to handle sending responses.
    """
    try:
        kwargs = build_kwargs(content, embed, ephemeral)
        if not interaction.response.is_done():
            await interaction.response.send_message(**kwargs)
        else:
            await interaction.followup.send(**kwargs)
        return True
    except discord.InteractionResponded as e:
        _log_interaction_warning("Attempted to respond to already responded interaction", interaction, e, skip_reason="already_responded")
        return await _try_followup(interaction, content, embed, ephemeral)
    except discord.HTTPException as e:
        _log_interaction_warning("HTTP error when responding to interaction", interaction, e, skip_reason="http_error")
        return False
    except Exception as e:
        _log_interaction_warning("Unexpected error when responding to interaction", interaction, e, skip_reason="unexpected_error")
        return False

async def _try_followup(interaction: discord.Interaction, content: Optional[str], 
                        embed: Optional[discord.Embed], ephemeral: bool) -> bool:
    """
    Internal function to handle followup responses.
    """
    try:
        kwargs = build_kwargs(content, embed, ephemeral)
        await interaction.followup.send(**kwargs)
        return True
    except Exception as followup_e:
        _log_interaction_warning("Followup failed after InteractionResponded", interaction, followup_e, skip_reason="followup_failed")
        return False

async def safe_followup_async(interaction: discord.Interaction, content: Optional[str] = None, 
                             embed: Optional[discord.Embed] = None, ephemeral: bool = False) -> bool:
    """
    Safely send a followup message to a Discord interaction without raising exceptions.
    
    Args:
        interaction: The Discord interaction to send followup to
        content: Optional text content for the followup
        embed: Optional embed for the followup
        ephemeral: Whether the followup should be ephemeral (only visible to the user)
        
    Returns:
        bool: True if the followup was sent successfully, False otherwise
    """
    if interaction.is_expired():
        _log_interaction_warning("Skipping followup to expired interaction", interaction, skip_reason="interaction_expired")
        return False
    
    try:
        kwargs = build_kwargs(content, embed, ephemeral)
        await interaction.followup.send(**kwargs)
        return True
    except discord.HTTPException as e:
        _log_interaction_warning("HTTP error when sending followup to interaction", interaction, e, skip_reason="http_error")
        return False
    except Exception as e:
        _log_interaction_warning("Unexpected error when sending followup to interaction", interaction, e, skip_reason="unexpected_error")
        return False
