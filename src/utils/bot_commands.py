import discord
import os
import logging
import uuid
import traceback
import asyncio
import time
from discord.ext import commands
from discord import app_commands
from typing import Dict, Any, Optional, List, Tuple, Callable

from .discopanel_api import DiscopanelAPI, ServerInfo, ApiResponse, DiscopanelAPIError
from .token_manager import TokenManager, TokenManagerError
from .monitoring import capture_exception, add_breadcrumb
from .discord_utils import can_respond, safe_respond_async, safe_followup_async

logger = logging.getLogger(__name__)

SERVER_ID_FIELD = "Server ID"
TIMEOUT_MESSAGE = "⚠️ Discopanel API timed-out."
BOT_FOOTER_TEXT = "Discopanel Bot"
START_COMMAND_COOLDOWN = 120  # seconds


def _has_valid_credentials(bot) -> bool:
    """Check if bot has valid Discopanel credentials"""
    return bool(bot.discopanel_url and bot.discopanel_username and bot.discopanel_password)


def _get_auth_for_api(bot):
    """Return TokenManager for API calls."""
    if bot.token_manager:
        return bot.token_manager
    raise ValueError("No valid authentication method available")


class DiscopanelBot(commands.Bot):
    """Extended Bot class with Discopanel configuration"""

    MISSING_CONFIG_ERROR = "Bot configuration is missing"

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.discopanel_url: Optional[str] = None
        self.discopanel_username: Optional[str] = None
        self.discopanel_password: Optional[str] = None
        self.server_id: str = self._get_server_id()
        self.token_manager: Optional[TokenManager] = None
        self.auth_mode: str = "unknown"
        self.last_start_command: Dict[int, float] = {}

    def _get_server_id(self) -> str:
        server_id_str = os.getenv('SERVER_ID')
        if not server_id_str:
            raise ValueError("SERVER_ID environment variable is required")
        try:
            uuid_obj = uuid.UUID(server_id_str)
        except ValueError:
            raise ValueError("SERVER_ID must be a valid UUID")
        return str(uuid_obj)

    async def cleanup(self) -> None:
        if self.token_manager:
            logger.info("Cleaning up TokenManager...")
            try:
                await self.token_manager.close()
                logger.debug("TokenManager cleanup completed")
            except Exception as e:
                logger.error(f"Error during TokenManager cleanup: {e}")


def _add_success_fields(embed: discord.Embed, response: ApiResponse, server_id: str):
    embed.add_field(name=SERVER_ID_FIELD, value=str(server_id), inline=True)
    if response.data and isinstance(response.data, dict):
        for key, value in response.data.items():
            if key not in ['server_id', 'id'] and value is not None:
                embed.add_field(name=key.replace('_', ' ').title(), value=str(value), inline=True)


def _add_failure_fields(embed: discord.Embed, response: ApiResponse, server_id: str):
    embed.add_field(name=SERVER_ID_FIELD, value=str(server_id), inline=True)
    if response.error_code:
        embed.add_field(name="Error Code", value=str(response.error_code), inline=True)


def create_response_embed(bot, response: ApiResponse, action: str, server_id: str) -> discord.Embed:
    """Create a formatted embed for API responses"""
    if response.success:
        embed = discord.Embed(
            title=f"✅ {action} Successful",
            description=response.message,
            color=discord.Color.green(),
            timestamp=discord.utils.utcnow()
        )
        _add_success_fields(embed, response, server_id)
    else:
        embed = discord.Embed(
            title=f"❌ {action} Failed",
            description=response.message,
            color=discord.Color.red(),
            timestamp=discord.utils.utcnow()
        )
        _add_failure_fields(embed, response, server_id)
    embed.set_footer(text=BOT_FOOTER_TEXT, icon_url=bot.user.avatar.url if bot.user and bot.user.avatar else None)
    return embed


def _derive_server_state(server: ServerInfo) -> Tuple[str, str, discord.Color]:
    status_raw = (server.status or "UNKNOWN").upper()
    if "RUN" in status_raw:
        return "🟢", "Running", discord.Color.green()
    if "START" in status_raw:
        return "🟡", "Starting", discord.Color.gold()
    if "STOP" in status_raw:
        return "🔴", "Stopped", discord.Color.dark_red()
    if "RESTART" in status_raw:
        return "🔄", "Restarting", discord.Color.blue()
    if "ERROR" in status_raw or "FAIL" in status_raw or "UNHEALTHY" in status_raw:
        return "💥", "Issue", discord.Color.red()
    return "⚪", status_raw.title(), discord.Color.light_grey()


def _format_players(server: ServerInfo) -> str:
    try:
        if server.players_online is not None and server.max_players is not None:
            return f"{int(server.players_online)}/{int(server.max_players)}"
        if server.players_online is not None:
            return f"{int(server.players_online)}/?"
        if server.max_players is not None:
            return f"?/{int(server.max_players)}"
    except (ValueError, TypeError):
        pass
    return "Unknown"


def _format_memory(server: ServerInfo) -> str:
    if server.memory_usage is None and server.memory is None:
        return "Unknown"
    parts: List[str] = []
    if server.memory_usage is not None:
        try:
            value = float(server.memory_usage)
            # Heuristic: if very large, treat as bytes; otherwise assume MB
            if value > 1024 * 1024:
                mb_used = value / (1024 * 1024)
            else:
                mb_used = value
            if mb_used >= 1024:
                gb_used = mb_used / 1024
                parts.append(f"{gb_used:.2f} GB used")
            else:
                parts.append(f"{mb_used:.1f} MB used")
        except Exception:
            parts.append(str(server.memory_usage))
    if server.memory is not None:
        if server.memory >= 1024:
            parts.append(f"{server.memory/1024:.2f} GB limit")
        else:
            parts.append(f"{server.memory} MB limit")
    return " / ".join(parts)


def create_status_embed(bot, server: ServerInfo) -> discord.Embed:
    status_emoji, status_text, color = _derive_server_state(server)
    server_name = server.name or "Unknown Server"
    description = f"{status_emoji} **{status_text}**"
    embed = discord.Embed(
        title=f"🧱 {server_name} (MC)",
        description=description,
        color=color,
        timestamp=discord.utils.utcnow()
    )

    embed.add_field(name="🆔 Server ID", value=str(server.id), inline=False)
    embed.add_field(name="🎮 Version", value=server.mc_version or "Unknown", inline=True)
    embed.add_field(name="🪓 Loader", value=server.mod_loader or "Unknown", inline=True)
    embed.add_field(name="👥 Players", value=_format_players(server), inline=True)
    embed.add_field(name="🖥️ CPU", value=f"{server.cpu_percent:.1f}%" if server.cpu_percent is not None else "Unknown", inline=True)
    embed.add_field(name="📦 Memory", value=_format_memory(server), inline=True)
    if server.tps is not None:
        embed.add_field(name="⏱️ TPS", value=f"{server.tps:.2f}", inline=True)

    embed.set_footer(
        text=BOT_FOOTER_TEXT,
        icon_url=bot.user.avatar.url if bot.user and bot.user.avatar else None
    )
    return embed


def check_start_command_cooldown(bot, user_id: int) -> Tuple[bool, Optional[float]]:
    current_time = time.time()
    last_command_time = bot.last_start_command.get(user_id, 0)
    time_since_last = current_time - last_command_time

    if time_since_last < START_COMMAND_COOLDOWN:
        time_remaining = START_COMMAND_COOLDOWN - time_since_last
        return True, time_remaining

    return False, None


def update_start_command_timestamp(bot, user_id: int):
    bot.last_start_command[user_id] = time.time()


async def perform_startup_auth_check(bot) -> bool:
    logger.info(f"Performing startup authentication check using {bot.auth_mode} mode")

    if not _has_valid_credentials(bot):
        logger.error("Startup authentication check failed - no valid credentials")
        return False

    try:
        auth_method = _get_auth_for_api(bot)
        async with DiscopanelAPI(bot.discopanel_url, auth_method) as api:
            try:
                async with asyncio.timeout(15):
                    response = await api.get_server(bot.server_id)

                if response.success:
                    logger.info("Startup authentication check successful - server retrieved")
                    return True
                else:
                    logger.error(f"Startup authentication check failed - API returned error: {response.message}")
                    return False

            except asyncio.TimeoutError:
                logger.error("Startup authentication check failed - API timeout")
                return False

    except TokenManagerError as e:
        logger.error(f"Startup authentication check failed - TokenManager error: {e}")
        return False
    except DiscopanelAPIError as e:
        logger.error(f"Startup authentication check failed - API error: {e}")
        return False
    except Exception as e:
        logger.error(f"Startup authentication check failed - unexpected error: {e}")
        return False


async def on_ready_handler(bot):
    logger.info(f'{bot.user} has connected to Discord!')
    logger.info('Bot is ready to manage Discopanel servers')

    guild_id = os.getenv("GUILD_ID")
    if guild_id:
        try:
            guild = discord.Object(id=int(guild_id))
            bot.tree.copy_global_to(guild=guild)
            synced = await bot.tree.sync(guild=guild)
            logger.info(f"Synced {len(synced)} slash commands to guild {guild_id}")
        except Exception:
            logger.error("Guild sync failed:\n%s", traceback.format_exc())

    try:
        synced = await bot.tree.sync()
        logger.info(f"Synced {len(synced)} slash commands globally")
    except Exception:
        logger.error("Global sync failed:\n%s", traceback.format_exc())

    activity = discord.Activity(
        type=discord.ActivityType.watching,
        name="Discopanel servers"
    )
    await bot.change_presence(activity=activity)


def handle_missing_permissions(interaction: discord.Interaction) -> str:
    return "❌ You don't have permission to use this command."


def handle_command_on_cooldown(original_error: app_commands.CommandOnCooldown) -> str:
    return f"❌ Command is on cooldown. Try again in {original_error.retry_after:.2f} seconds."


def handle_transformer_error() -> str:
    return "❌ Invalid argument provided. Please check your input."


def handle_value_error(original_error: ValueError) -> str:
    return f"❌ Invalid value: {str(original_error)}"


def log_error_breadcrumb(interaction: discord.Interaction, original_error: Exception) -> None:
    add_breadcrumb(
        message="Application command error occurred",
        category="discord_command",
        level="error",
        data={
            "command": interaction.command.name if interaction.command else "unknown",
            "error_type": type(original_error).__name__,
            "user_id": interaction.user.id if interaction.user else None,
            "guild_id": interaction.guild.id if interaction.guild else None
        }
    )


async def send_error_response(interaction: discord.Interaction, error_message: str) -> None:
    if can_respond(interaction):
        await safe_respond_async(interaction, error_message, ephemeral=True)
    else:
        await safe_followup_async(interaction, error_message, ephemeral=True)


async def handle_secondary_error(interaction: discord.Interaction, secondary_error: Exception) -> None:
    logger.error(f"Secondary error in error handler: {secondary_error}")
    logger.error(f"Error handler traceback:\n{traceback.format_exc()}")

    try:
        generic_message = "❌ An error occurred while processing your command."
        await send_error_response(interaction, generic_message)
    except Exception:
        logger.error(f"Failed to send any error response for interaction {interaction.id}")


def handle_unexpected_error(interaction: discord.Interaction, original_error: Exception) -> str:
    logger.error(f"Unexpected error in application command: {original_error}")
    capture_exception(original_error, {
        "component": "discord_command",
        "command": interaction.command.name if interaction.command else "unknown",
        "user_id": interaction.user.id if interaction.user else None,
        "guild_id": interaction.guild.id if interaction.guild else None,
        "channel_id": interaction.channel.id if interaction.channel else None
    })
    error_message = "❌ " + str(original_error)
    if len(error_message) > 2000:
        error_message = "❌ An unexpected error occurred. Please try again later."
    return error_message


async def on_app_command_error_handler(interaction: discord.Interaction, error: app_commands.AppCommandError) -> None:
    try:
        original_error = error
        if isinstance(error, app_commands.CommandInvokeError):
            original_error = error.original

        log_error_breadcrumb(interaction, original_error)

        error_handlers: Dict[type, Callable[..., str]] = {
            app_commands.MissingPermissions: handle_missing_permissions,
            app_commands.CommandOnCooldown: handle_command_on_cooldown,
            app_commands.TransformerError: handle_transformer_error,
            ValueError: handle_value_error
        }

        handler = error_handlers.get(type(original_error), handle_unexpected_error)

        if handler is handle_missing_permissions:
            error_message = handler(interaction)
        elif handler is handle_transformer_error:
            error_message = handler()
        elif handler is handle_unexpected_error:
            error_message = handler(interaction, original_error)
        else:
            error_message = handler(original_error)

        await send_error_response(interaction, error_message)

    except Exception as secondary_error:
        await handle_secondary_error(interaction, secondary_error)


def get_start_command(bot):
    @app_commands.command(name="start", description="Start the Discopanel server")
    async def start_server(interaction: discord.Interaction) -> None:
        await interaction.response.defer(thinking=True)
        if not _has_valid_credentials(bot):
            raise ValueError(bot.MISSING_CONFIG_ERROR)

        user_id = interaction.user.id
        is_on_cooldown, time_remaining = check_start_command_cooldown(bot, user_id)
        if is_on_cooldown:
            minutes = int(time_remaining // 60)
            seconds = int(time_remaining % 60)
            cooldown_message = f"⏰ Start command was recently used. Please wait {minutes}m {seconds}s before using it again."
            await safe_followup_async(interaction, cooldown_message, ephemeral=True)
            return

        auth_method = _get_auth_for_api(bot)
        async with DiscopanelAPI(bot.discopanel_url, auth_method) as api:
            try:
                async with asyncio.timeout(10):
                    response = await api.start_server(bot.server_id)
            except asyncio.TimeoutError:
                await safe_followup_async(interaction, TIMEOUT_MESSAGE, ephemeral=True)
                return

            update_start_command_timestamp(bot, user_id)
            initial_embed = create_response_embed(bot, response, "Server Start", bot.server_id)
            message = await interaction.followup.send(embed=initial_embed)

            if response.success:
                try:
                    async with asyncio.timeout(20):
                        status_response = await api.get_server(bot.server_id)
                        if status_response.success and isinstance(status_response.data, ServerInfo):
                            status_embed = create_status_embed(bot, status_response.data)
                            await message.edit(embed=status_embed)
                except Exception as e:
                    logger.debug(f"Could not refresh status after start: {e}")
    return start_server


def get_stop_command(bot):
    @app_commands.command(name="stop", description="Stop the Discopanel server")
    async def stop_server(interaction: discord.Interaction) -> None:
        await interaction.response.defer(thinking=True)
        if not _has_valid_credentials(bot):
            raise ValueError(bot.MISSING_CONFIG_ERROR)

        auth_method = _get_auth_for_api(bot)
        async with DiscopanelAPI(bot.discopanel_url, auth_method) as api:
            try:
                async with asyncio.timeout(10):
                    response = await api.stop_server(bot.server_id)
            except asyncio.TimeoutError:
                await safe_followup_async(interaction, TIMEOUT_MESSAGE, ephemeral=True)
                return
            embed = create_response_embed(bot, response, "Server Stop", bot.server_id)
            await interaction.followup.send(embed=embed)
    return stop_server


def get_restart_command(bot):
    @app_commands.command(name="restart", description="Restart the Discopanel server")
    async def restart_server(interaction: discord.Interaction) -> None:
        await interaction.response.defer(thinking=True)
        if not _has_valid_credentials(bot):
            raise ValueError(bot.MISSING_CONFIG_ERROR)

        auth_method = _get_auth_for_api(bot)
        async with DiscopanelAPI(bot.discopanel_url, auth_method) as api:
            try:
                async with asyncio.timeout(10):
                    response = await api.restart_server(bot.server_id)
            except asyncio.TimeoutError:
                await safe_followup_async(interaction, TIMEOUT_MESSAGE, ephemeral=True)
                return
            embed = create_response_embed(bot, response, "Server Restart", bot.server_id)
            await interaction.followup.send(embed=embed)
    return restart_server


def get_status_command(bot):
    @app_commands.command(name="status", description="Check server status")
    async def check_status(interaction: discord.Interaction) -> None:
        await interaction.response.defer(thinking=True)
        if not _has_valid_credentials(bot):
            raise ValueError(bot.MISSING_CONFIG_ERROR)

        auth_method = _get_auth_for_api(bot)
        async with DiscopanelAPI(bot.discopanel_url, auth_method) as api:
            try:
                async with asyncio.timeout(10):
                    response = await api.get_server(bot.server_id)
            except asyncio.TimeoutError:
                await safe_followup_async(interaction, TIMEOUT_MESSAGE, ephemeral=True)
                return
            if response.success and isinstance(response.data, ServerInfo):
                embed = create_status_embed(bot, response.data)
                await interaction.followup.send(embed=embed)
            else:
                embed = create_response_embed(bot, response, "Server Status", bot.server_id)
                await interaction.followup.send(embed=embed)
    return check_status


def get_help_command(bot):
    @app_commands.command(name="help", description="Show available commands")
    async def help_command(interaction: discord.Interaction) -> None:
        embed = discord.Embed(
            title=f"🤖 {BOT_FOOTER_TEXT} Commands",
            description="Available slash commands for managing your Minecraft servers",
            color=discord.Color.blue(),
            timestamp=discord.utils.utcnow()
        )
        commands_info: List[Tuple[str, str]] = [
            ("/start", "Start the server"),
            ("/stop", "Stop the server"),
            ("/restart", "Restart the server"),
            ("/status", "Check server status and statistics"),
            ("/help", "Show this help message")
        ]
        for cmd, desc in commands_info:
            embed.add_field(name=cmd, value=desc, inline=False)
        embed.set_footer(text=f"Managing server ID: {bot.server_id}")
        await interaction.response.send_message(embed=embed)
    return help_command


def create_bot() -> DiscopanelBot:
    intents = discord.Intents.default()
    intents.message_content = True
    bot = DiscopanelBot(command_prefix=None, intents=intents, help_command=None)

    bot.discopanel_url = os.getenv('DISCOPANEL_URL')
    bot.discopanel_username = os.getenv('DISCOPANEL_USERNAME')
    bot.discopanel_password = os.getenv('DISCOPANEL_PASSWORD')

    if not bot.discopanel_url:
        raise ValueError("DISCOPANEL_URL environment variable is required")

    if not (bot.discopanel_username and bot.discopanel_password):
        raise ValueError(
            "Invalid Discopanel credentials. DISCOPANEL_USERNAME and DISCOPANEL_PASSWORD are required."
        )

    bot.auth_mode = "credentials"
    bot.token_manager = TokenManager(bot.discopanel_url, bot.discopanel_username, bot.discopanel_password)
    logger.info("Authentication mode: Username/Password with TokenManager")

    @bot.event
    async def on_ready():
        await on_ready_handler(bot)

    @bot.tree.error
    async def on_app_command_error(interaction: discord.Interaction, error: app_commands.AppCommandError):
        await on_app_command_error_handler(interaction, error)

    bot.tree.add_command(get_start_command(bot))
    bot.tree.add_command(get_stop_command(bot))
    bot.tree.add_command(get_restart_command(bot))
    bot.tree.add_command(get_status_command(bot))
    bot.tree.add_command(get_help_command(bot))

    return bot
