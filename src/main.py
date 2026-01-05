import os
import asyncio
import logging
from dotenv import load_dotenv

# Support running as a module (`python -m src.main`) or as a script (`python src/main.py`)
try:  # package-style imports
    from .utils.bot_commands import create_bot  # type: ignore
    from .utils.monitoring import initialize_sentry, capture_exception, get_monitoring_status  # type: ignore
    from .utils.config_validation import perform_startup_health_check  # type: ignore
except ImportError:  # script-style fallback
    from utils.bot_commands import create_bot  # type: ignore
    from utils.monitoring import initialize_sentry, capture_exception, get_monitoring_status  # type: ignore
    from utils.config_validation import perform_startup_health_check  # type: ignore

# Load environment variables
load_dotenv()

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)

async def main() -> None:
    """Main function to run the bot"""
    # Initialize monitoring system (optional)
    initialize_sentry()
    monitoring_status = get_monitoring_status()
    logging.info(f"Monitoring status: {monitoring_status}")
    
    # Perform comprehensive startup health check (includes all validation)
    logging.info("Performing comprehensive startup validation...")
    health_check_success = await perform_startup_health_check()
    if not health_check_success:
        logging.error("Comprehensive startup validation failed - bot will not start")
        return
    
    # Initialize and run the bot
    bot = create_bot()
    
    try:
        discord_token = os.getenv('DISCORD_TOKEN')
        if not discord_token:
            logging.error("DISCORD_TOKEN environment variable is required")
            return
        await bot.start(discord_token)
    except KeyboardInterrupt:
        logging.info("Bot shutdown requested by user")
    except Exception as e:
        logging.error(f"Bot crashed with error: {e}")
        capture_exception(e, {
            'component': 'main',
            'stage': 'bot_startup',
            'server_id': os.getenv('SERVER_ID')
        })
    finally:
        await bot.cleanup()
        await bot.close()

if __name__ == "__main__":
    asyncio.run(main())
