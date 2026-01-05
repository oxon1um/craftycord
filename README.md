# Discopanel Discord Bot

Minimal Discord bot to start, stop, restart, and check status of a Discopanel-managed Minecraft server.

## Quick Start
1) Install deps: `pip install -r requirements.txt`
2) Create `.env`:
```
DISCORD_TOKEN=your_discord_bot_token
DISCOPANEL_URL=http://your-discopanel-host
# one of:
DISCOPANEL_TOKEN=api_token
DISCOPANEL_USERNAME=username
DISCOPANEL_PASSWORD=password
SERVER_ID=server-uuid
GUILD_ID=optional_guild_id_for_fast_sync
```
3) Run the bot: `python src/main.py`

Run tests: `python tests/run_tests.py`
