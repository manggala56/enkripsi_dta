import json
import os

DB_FILE = "database.json"

def init_db():
    if not os.path.exists(DB_FILE):
        default_data = {
            "users": {},
            "messages": []
        }
        with open(DB_FILE, "w", encoding="utf-8") as f:
            json.dump(default_data, f, indent=4)

def load_db():
    init_db()
    try:
        with open(DB_FILE, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return {"users": {}, "messages": []}

def save_db(data):
    with open(DB_FILE, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=4)

def save_user(username, public_key, private_key):
    db = load_db()
    db["users"][username] = {
        "public_key": [str(public_key[0]), str(public_key[1])],
        "private_key": [str(private_key[0]), str(private_key[1])]
    }
    save_db(db)

def get_user_keys(username):
    db = load_db()
    user = db["users"].get(username)
    if not user:
        return None
    pub = (int(user["public_key"][0]), int(user["public_key"][1]))
    priv = (int(user["private_key"][0]), int(user["private_key"][1]))
    return {"public": pub, "private": priv}

def append_message(sender, receiver, payload):
    db = load_db()
    db["messages"].append({
        "sender": sender,
        "receiver": receiver,
        "payload": payload
    })
    save_db(db)

def get_all_messages():
    db = load_db()
    return db.get("messages", [])

def clear_db():
    default_data = {"users": {}, "messages": []}
    save_db(default_data)