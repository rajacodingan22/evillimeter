import json
import urllib.request
import urllib.error


def send_telegram(token, chat_id, message):
    if not token or not chat_id:
        return False
    try:
        url = "https://api.telegram.org/bot{}/sendMessage".format(token)
        data = json.dumps(
            {"chat_id": chat_id, "text": message, "parse_mode": "HTML"}
        ).encode()
        req = urllib.request.Request(
            url, data=data, headers={"Content-Type": "application/json"}
        )
        urllib.request.urlopen(req, timeout=10)
        return True
    except (urllib.error.URLError, urllib.error.HTTPError, OSError):
        return False


def send_discord(webhook_url, message):
    if not webhook_url:
        return False
    try:
        data = json.dumps({"content": message}).encode()
        req = urllib.request.Request(
            webhook_url, data=data, headers={"Content-Type": "application/json"}
        )
        urllib.request.urlopen(req, timeout=10)
        return True
    except (urllib.error.URLError, urllib.error.HTTPError, OSError):
        return False


def send_notification(db, message):
    token = db.get_setting("telegram_token", "")
    chat_id = db.get_setting("telegram_chat_id", "")
    discord_url = db.get_setting("discord_webhook", "")

    sent = False
    if token and chat_id:
        if send_telegram(token, chat_id, message):
            sent = True
    if discord_url:
        if send_discord(discord_url, message):
            sent = True
    return sent
