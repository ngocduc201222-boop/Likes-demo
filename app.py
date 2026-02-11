#!/usr/bin/env python3
import json
import requests
import threading
import time
import asyncio
import aiohttp

from datetime import datetime, timedelta, timezone
from flask import Flask, jsonify, request
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
from protobuf_decoder.protobuf_decoder import Parser

# --- Config AES ---
key = b"Yg&tc%DEuh6%Zc^8"
iv = b"6oyZDr22E3ychjM%"

app = Flask(__name__)

accounts_data = {}
account_index = 0
accounts_lock = threading.Lock()
tokens = {}
tokens_lock = threading.Lock()
used_uids = {}
uids_lock = threading.Lock()

gringay = None

api_keys = {
    "372012": {"exp": "30/7/2080", "remain": 999, "max_remain": 999, "last_reset": None}
}

def is_key_valid(key):
    if key not in api_keys:
        return None
    expiration_date = datetime.strptime(api_keys[key]["exp"], "%d/%m/%Y")
    if datetime.utcnow() > expiration_date:
        return False
    current_date = datetime.utcnow().date()
    if api_keys[key]["remain"] <= 0:
        return False
    if api_keys[key].get("last_reset") != current_date:
        api_keys[key]["remain"] = api_keys[key]["max_remain"]
        api_keys[key]["last_reset"] = current_date
    return api_keys[key]["remain"] > 0

def load_accounts():
    global accounts_data
    try:
        with open('account.json', 'r') as f:
            accounts_data = json.load(f)
        print(f"{len(accounts_data)} ACC loaded")
    except (FileNotFoundError, json.JSONDecodeError):
        accounts_data = {}
        print("No account.json or parse error - accounts_data empty")

def get_next_accounts(num=200):
    global account_index, accounts_data
    with accounts_lock:
        if not accounts_data:
            load_accounts()
        if not accounts_data:
            return []

        uids = list(accounts_data.keys())
        selected_accounts = []

        for i in range(min(num, len(uids))):
            if account_index >= len(uids):
                account_index = 0
            uid = uids[account_index]
            password = accounts_data[uid]
            selected_accounts.append((uid, password))
            account_index += 1

        return selected_accounts

def Encrypt(number):
    number = int(number)
    if number < 0:
        return False
    encoded_bytes = []
    while True:
        byte = number & 0x7F
        number >>= 7
        if number:
            byte |= 0x80
        encoded_bytes.append(byte)
        if not number:
            break
    return bytes(encoded_bytes)

def create_varint_field(field_number, value):
    field_header = (field_number << 3) | 0
    return Encrypt(field_header) + Encrypt(value)

def create_length_delimited_field(field_number, value):
    field_header = (field_number << 3) | 2
    encoded_value = value.encode() if isinstance(value, str) else value
    return Encrypt(field_header) + Encrypt(len(encoded_value)) + encoded_value

def create_protobuf_packet(fields):
    packet = bytearray()
    for field, value in fields.items():
        if isinstance(value, dict):
            nested_packet = create_protobuf_packet(value)
            packet.extend(create_length_delimited_field(field, nested_packet))
        elif isinstance(value, int):
            packet.extend(create_varint_field(field, value))
        elif isinstance(value, str) or isinstance(value, bytes):
            packet.extend(create_length_delimited_field(field, value))
    return packet

def parse_results(parsed_results):
    result_dict = {}
    for result in parsed_results:
        if result.field not in result_dict:
            result_dict[result.field] = []
        field_data = {}
        if result.wire_type in ["varint", "string", "bytes"]:
            field_data = result.data
        elif result.wire_type == "length_delimited":
            field_data = parse_results(result.data.results)
        result_dict[result.field].append(field_data)
    return {key: value[0] if len(value) == 1 else value for key, value in result_dict.items()}

def protobuf_dec(hex_str):
    try:
        return json.dumps(parse_results(Parser().parse(hex_str)), ensure_ascii=False)
    except Exception:
        return "{}"

def encrypt_api(hex_str):
    try:
        plain_text = bytes.fromhex(hex_str)
        cipher = AES.new(key, AES.MODE_CBC, iv)
        cipher_text = cipher.encrypt(pad(plain_text, AES.block_size))
        return cipher_text.hex()
    except Exception:
        return ""

async def get_token(acc, session):
    try:
        if isinstance(acc, (list, tuple)):
            uid, password = acc[0], acc[1]
        elif isinstance(acc, str):
            if ":" in acc:
                uid, password = acc.split(":", 1)
            else:
                uid, password = acc, ""
        else:
            return None

        uid = str(uid).strip()
        password = str(password).strip()
        if not uid:
            return None

        url = f"Https://garena-freefire-vn-jwt.vercel.app/token?uid={uid}&password={password}"
        async with session.get(url) as response:
            text = await response.text()

            print("=" * 60)
            print(f"[get_token] UID: {uid}")
            print(f"[get_token] STATUS: {response.status}")
            print(f"[get_token] RESPONSE (preview): {text[:600]}")

            if response.status not in (200, 201):
                return None

            try:
                data = json.loads(text)
            except:
                return None

            def find_token_only(obj):
                if isinstance(obj, dict):
                    if "token" in obj and isinstance(obj["token"], str) and obj["token"]:
                        return obj["token"]
                    for v in obj.values():
                        r = find_token_only(v)
                        if r:
                            return r
                elif isinstance(obj, list):
                    for i in obj:
                        r = find_token_only(i)
                        if r:
                            return r
                return None

            return find_token_only(data)

    except Exception:
        return None

async def refresh_tokens():
    global tokens
    try:
        accounts = get_next_accounts(200)
        if accounts:
            timeout = aiohttp.ClientTimeout(total=30)
            async with aiohttp.ClientSession(timeout=timeout) as session:
                tasks = [get_token(f"{uid}:{password}", session) for uid, password in accounts]
                new_tokens = await asyncio.gather(*tasks)
                valid_tokens = [token for token in new_tokens if isinstance(token, str) and token]
                with tokens_lock:
                    tokens = {token: 0 for token in valid_tokens}
    except Exception:
        with tokens_lock:
            tokens = {}
    threading.Timer(12345, lambda: asyncio.run(refresh_tokens())).start()

async def clean_and_replace_tokens():
    global tokens
    tokens_to_remove = []
    with tokens_lock:
        tokens_to_remove = [token for token, count in tokens.items() if count >= 27]
    if not tokens_to_remove:
        return
    accounts = get_next_accounts(len(tokens_to_remove) + 5)
    if accounts:
        try:
            timeout = aiohttp.ClientTimeout(total=30)
            async with aiohttp.ClientSession(timeout=timeout) as session:
                tasks = [get_token(f"{uid}:{password}", session) for uid, password in accounts]
                new_tokens = await asyncio.gather(*tasks, return_exceptions=True)
                valid_new_tokens = [token for token in new_tokens if isinstance(token, str) and token]

                with tokens_lock:
                    for old_token in tokens_to_remove:
                        if old_token in tokens:
                            del tokens[old_token]
                    for new_token in valid_new_tokens:
                        tokens[new_token] = 0
        except Exception:
            with tokens_lock:
                for old_token in tokens_to_remove:
                    if old_token in tokens:
                        del tokens[old_token]

async def generate_additional_tokens(needed_tokens):
    try:
        accounts = get_next_accounts(needed_tokens + 10)
        if not accounts:
            return []
        timeout = aiohttp.ClientTimeout(total=30)
        async with aiohttp.ClientSession(timeout=timeout) as session:
            tasks = [get_token(f"{uid}:{password}", session) for uid, password in accounts]
            new_tokens = await asyncio.gather(*tasks, return_exceptions=True)
            valid_tokens = [token for token in new_tokens if isinstance(token, str) and token]
            with tokens_lock:
                for token in valid_tokens:
                    tokens[token] = 0
            return valid_tokens
    except Exception:
        return []

async def refresh_token():
    global gringay
    try:
        timeout = aiohttp.ClientTimeout(total=30)
        async with aiohttp.ClientSession(timeout=timeout) as s:
            gringay = await get_token("4454183302:hoaian@TGTNOCTTX", s)
    except Exception:
        pass
    threading.Timer(13500, lambda: asyncio.run(refresh_token())).start()

async def LikesProfile(payload, session, token):
    try:
        url = "https://clientbp.ggwhitehawk.com/LikeProfile"
        headers = {
            "ReleaseVersion": "OB52",
            "X-GA": "v1 1",
            "Authorization": f"Bearer {token}",
            "Host": "clientbp.ggwhitehawk.com"
        }
        async with session.post(url, headers=headers, data=payload, timeout=10) as res:
            return res.status == 200
    except Exception:
        return False

async def GetPlayerPersonalShow(payload, session):
    global gringay
    try:
        url = "https://clientbp.ggwhitehawk.com/GetPlayerPersonalShow"
        headers = {
            "ReleaseVersion": "OB52",
            "X-GA": "v1 1",
            "Authorization": f"Bearer {gringay}",
            "Host": "clientbp.ggwhitehawk.com"
        }
        async with session.post(url, headers=headers, data=payload) as res:
            if res.status == 200:
                r = await res.read()
                return json.loads(protobuf_dec(r.hex()))
            return None
    except Exception:
        return None

def add_token_usage(_tokens):
    with tokens_lock:
        for token in _tokens:
            if token in tokens:
                tokens[token] += 1

async def sendLikes(uid):
    global used_uids, tokens
    today = datetime.now().date()
    with uids_lock:
        if uid in used_uids and used_uids[uid] == today:
            return {"Failed": "Maximum like received"}, 200

    with tokens_lock:
        available_tokens = {k: v for k, v in tokens.items() if v < 27}
        token_list = list(available_tokens.keys())

    if len(token_list) < 200:
        needed_tokens = 200 - len(token_list)
        new_tokens = await generate_additional_tokens(needed_tokens)
        with tokens_lock:
            available_tokens = {k: v for k, v in tokens.items() if v < 27}
            token_list = list(available_tokens.keys())

        if len(token_list) < 1:
            return {"message": "{}".format(len(token_list))}, 200

    _tokens = token_list[:200]
    packet = create_protobuf_packet({1: int(uid), 2: 1}).hex()
    encrypted_packet = encrypt_api(packet)
    if not encrypted_packet:
        return "null", 201
    payload = bytes.fromhex(encrypted_packet)

    timeout = aiohttp.ClientTimeout(total=5)
    async with aiohttp.ClientSession(timeout=timeout) as session:
        InfoBefore = await GetPlayerPersonalShow(payload, session)
        if not InfoBefore or "1" not in InfoBefore or "21" not in InfoBefore["1"]:
            return {"Failse": "Account does not exist"}, 200

        LikesBefore = int(InfoBefore["1"]["21"])
        start_time = time.time()

        tasks = [LikesProfile(payload, session, token) for token in _tokens]
        await asyncio.gather(*tasks, return_exceptions=True)

        with uids_lock:
            used_uids[uid] = today

        InfoAfter = await GetPlayerPersonalShow(payload, session)
        if not InfoAfter or "1" not in InfoAfter or "21" not in InfoAfter["1"]:
            return "null", 201

        LikesAfter = int(InfoAfter["1"]["21"])
        LikesAdded = LikesAfter - LikesBefore

        add_token_usage(_tokens)
        asyncio.create_task(clean_and_replace_tokens())

        if LikesAdded <= 0:
            return {"Failse": "Account Id '{}' with name '{}' has reached max likes today, try again tomorrow !".format(InfoBefore["1"]["1"], InfoBefore["1"]["3"])}, 200

        end_time = time.time()
        return {
            "result": {
                "User Info": {
                    "Account UID": InfoBefore["1"]["1"],
                    "Account Name": InfoBefore["1"]["3"],
                    "Account Region": InfoBefore["1"]["5"],
                    "Account Level": InfoBefore["1"]["6"],
                    "Account Likes": InfoBefore["1"]["21"]
                },
                "Likes Info": {
                    "Likes Before": LikesBefore,
                    "Likes After": LikesBefore + LikesAdded,
                    "Likes Added": LikesAdded,
                    "Likes start of day": max(0, LikesBefore + LikesAdded - 100),
                },
                "API": {
                    "speeds": "{:.1f}s".format(end_time - start_time),
                    "Success": True,
                }
            }
        }, 200

def reset_uids():
    global used_uids, account_index
    with uids_lock:
        used_uids = {}
        account_index = 0

def schedule_reset():
    now = datetime.now(timezone.utc)
    next_reset = datetime.combine(now.date(), datetime.min.time(), tzinfo=timezone.utc) + timedelta(days=1)
    delta_seconds = (next_reset - now).total_seconds()
    threading.Timer(delta_seconds, lambda: [reset_uids(), schedule_reset()]).start()

# --- Flask route ---
@app.route("/likes", methods=["GET"])
def FF_LIKES():
    uid = request.args.get("uid")
    key = request.args.get("keys")
    if is_key_valid(key) is None:
        return jsonify({"message": "key not found, To buy key contact tg @Tranducdev"}), 200
    if not uid:
        return 'UID missing!'
    try:
        uid = str(uid).strip()
    except:
        return '?'
    try:
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        result = loop.run_until_complete(sendLikes(uid))
        loop.close()
        return jsonify(result[0]), result[1]
    except Exception as e:
        return jsonify({"error": str(e)}), 500

# --- Main ---
if __name__ == "__main__":
    load_accounts()

    def background_tasks():
        try:
            asyncio.run(refresh_tokens())
        except Exception:
            pass
        try:
            asyncio.run(refresh_token())
        except Exception:
            pass

    threading.Thread(target=background_tasks, daemon=True).start()
    schedule_reset()
    app.run(host="0.0.0.0", port=2026, threaded=True)