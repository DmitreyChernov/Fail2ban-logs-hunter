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
    r"(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})[,.]\d+\s+fail2ban\.actions\[\d+\]:\s+NOTICE\s+\[([^\]]+)\]\s+Ban\s+([0-9a-fA-F.:]+)"
)

async def get_connection():
    ssl_ctx = ssl.create_default_context()
    ssl_ctx.check_hostname = False
    ssl_ctx.verify_mode = ssl.CERT_NONE
    
    return await asyncpg.connect(
        host=EXT_PG_HOST,
        port=EXT_PG_PORT,
        database=EXT_PG_DB,
        user=EXT_PG_USER,
        password=EXT_PG_PASSWORD,
        ssl=ssl_ctx
    )

async def write_ban(ban_time_str, jail, ip):
    try:
        ban_time = datetime.strptime(ban_time_str, "%Y-%m-%d %H:%M:%S")
        conn = await get_connection()
        try:
            await conn.execute("""
                INSERT INTO fail2ban_bans (server_id, ip, jail, first_seen, last_seen, ban_count)
                VALUES ($1, $2::inet, $3, $4, $4, 1)
                ON CONFLICT (server_id, ip, jail) DO UPDATE SET
                    last_seen = EXCLUDED.last_seen,
                    ban_count = fail2ban_bans.ban_count + 1,
                    updated_at = NOW()
            """, SERVER_ID, ip, jail, ban_time)
            logger.info(f"🟢 Бан успешно записан в БД: IP={ip}, Jail={jail}")
        finally:
            await conn.close()
    except Exception as e:
        logger.error(f"🔴 Ошибка записи бана IP={ip} в БД: {e}")

async def check_updates():
    """Фоновая задача проверки обновлений на GitHub раз в 5 минут"""
    logger.info("🔄 Задача автообновления запущена внутри скрипта")
    while True:
        await asyncio.sleep(300)
        try:
            if not os.path.exists("/project"):
                continue
                
            fetch_proc = await asyncio.create_subprocess_exec(
                "git", "-C", "/project", "fetch", "origin",
                stdout=asyncio.subprocess.DEVNULL, stderr=asyncio.subprocess.DEVNULL
            )
            await fetch_proc.wait()

            local_proc = await asyncio.create_subprocess_exec(
                "git", "-C", "/project", "rev-parse", "HEAD",
                stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.DEVNULL
            )
            stdout, _ = await local_proc.communicate()
            local_hash = stdout.decode().strip()

            remote_proc = await asyncio.create_subprocess_exec(
                "git", "-C", "/project", "rev-parse", "@{u}",
                stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.DEVNULL
            )
            stdout, _ = await remote_proc.communicate()
            remote_hash = stdout.decode().strip()

            if local_hash and remote_hash and local_hash != remote_hash:
                logger.info("🚀 Найдена новая версия на GitHub! Инициирую самообновление...")
                
                pull_proc = await asyncio.create_subprocess_exec("git", "-C", "/project", "pull")
                await pull_proc.wait()
                
                # ИСПРАВЛЕНО: используется классический docker-compose (через дефис)
                up_proc = await asyncio.create_subprocess_exec(
                    "docker-compose", "-f", "/project/docker-compose.yml", "up", "-d", "--build"
                )
                await up_proc.wait()
                
        except Exception as e:
            logger.error(f"⚠️ Ошибка при проверке обновлений: {e}")

async def tail_log():
    logger.info(f"Запуск мониторинга лога: {LOG_PATH}")
    logger.info(f"Сервер ID: {SERVER_ID}")
    
    asyncio.create_task(check_updates())
    
    while True:
        try:
            process = await asyncio.create_subprocess_exec(
                "tail", "-F", "-n", "0", LOG_PATH,
                stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE
            )
            logger.info("Процесс tail успешно запущен. Ожидание новых строк лога...")
            
            while True:
                line = await process.stdout.readline()
                if not line:
                    break
                
                line_str = line.decode("utf-8", errors="ignore").strip()
                match = BAN_REGEX.search(line_str)
                if match:
                    asyncio.create_task(write_ban(match.group(1), match.group(2), match.group(3)))
                    
        except Exception as e:
            logger.error(f"Ошибка в основном цикле tail: {e}")
        await asyncio.sleep(5)

if __name__ == "__main__":
    try:
        asyncio.run(tail_log())
    except KeyboardInterrupt:
        logger.info("Получен сигнал остановки")
