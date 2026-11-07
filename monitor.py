import asyncio
import asyncpg
import ssl
import re
import os
import logging
from datetime import datetime
from dotenv import load_dotenv

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s"
)
logger = logging.getLogger(__name__)

# Загружаем локальный конфиг (путь к реальному .env)
load_dotenv("/app/.env")
CONFIG_ENV_PATH = os.getenv("CONFIG_ENV_PATH", "")
SERVER_ID = os.getenv("SERVER_ID", "unknown-server")
LOG_PATH = os.getenv("LOG_PATH", "/var/log/fail2ban.log")

if not CONFIG_ENV_PATH:
    logger.error("CONFIG_ENV_PATH не задан в /app/.env")
    exit(1)

logger.info(f"Загружаем реальный .env из: {CONFIG_ENV_PATH}")
load_dotenv(CONFIG_ENV_PATH)

EXT_PG_HOST = os.getenv("EXT_PG_HOST", "")
EXT_PG_PORT = int(os.getenv("EXT_PG_PORT", "5432"))
EXT_PG_DB = os.getenv("EXT_PG_DB", "")
EXT_PG_USER = os.getenv("EXT_PG_USER", "")
EXT_PG_PASSWORD = os.getenv("EXT_PG_PASSWORD", "")

BAN_REGEX = re.compile(
    r"(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}),\d+\s+fail2ban\.actions\[\d+\]:\s+NOTICE\s+\[([^\]]+)\]\s+Ban\s+([0-9a-fA-F.:]+)"
)

async def get_connection():
    ssl_ctx = ssl.create_default_context()
    ssl_ctx.check_hostname = False
    ssl_ctx.verify_mode = ssl.CERT_NONE
    
    conn = await asyncpg.connect(
        host=EXT_PG_HOST,
        port=EXT_PG_PORT,
        database=EXT_PG_DB,
        user=EXT_PG_USER,
        password=EXT_PG_PASSWORD,
        ssl=ssl_ctx
    )
    return conn

async def write_ban(conn, ban_time_str, jail, ip):
    try:
        ban_time = datetime.strptime(ban_time_str, "%Y-%m-%d %H:%M:%S")
        await conn.execute("""
            INSERT INTO fail2ban_bans (server_id, ip, jail, first_seen, last_seen, ban_count)
            VALUES ($1, $2::inet, $3, $4, $4, 1)
            ON CONFLICT (server_id, ip, jail) DO UPDATE SET
                last_seen = EXCLUDED.last_seen,
                ban_count = fail2ban_bans.ban_count + 1,
                updated_at = NOW()
        """, SERVER_ID, ip, jail, ban_time)
        logger.info(f"Бан записан: IP={ip}, Jail={jail}")
    except Exception as e:
        logger.error(f"Ошибка записи бана IP={ip}: {e}")

async def tail_log():
    logger.info(f"Запуск мониторинга лога: {LOG_PATH}")
    logger.info(f"Сервер ID: {SERVER_ID}")
    
    while True:
        try:
            process = await asyncio.create_subprocess_exec(
                "tail", "-F", LOG_PATH,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            logger.info("Процесс tail запущен")
            
            conn = await get_connection()
            logger.info("Подключение к БД установлено")
            
            try:
                while True:
                    line = await process.stdout.readline()
                    if not line:
                        break
                    line_str = line.decode("utf-8", errors="ignore").strip()
                    match = BAN_REGEX.search(line_str)
                    if match:
                        await write_ban(conn, match.group(1), match.group(2), match.group(3))
            finally:
                await conn.close()
                process.terminate()
                await process.wait()
        except Exception as e:
            logger.error(f"Ошибка в цикле мониторинга: {e}")
            logger.info("Перезапуск через 5 секунд...")
            await asyncio.sleep(5)

if __name__ == "__main__":
    try:
        asyncio.run(tail_log())
    except KeyboardInterrupt:
        logger.info("Получен сигнал остановки")
