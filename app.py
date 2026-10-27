from flask import Flask, render_template, request, jsonify
import secrets
import itertools

app = Flask(__name__)

# Parameter kecil ini hanya untuk demo pembelajaran, bukan keamanan produksi.
P = 65537
G = 3
message_ids = itertools.count(1)
messages = []
keys = {}
DH = {}


def make_keypair():
    """Menghasilkan pasangan kunci ElGamal demo."""
    private = secrets.randbelow(P - 3) + 2
    public = pow(G, private, P)
    return {"private": private, "public": public}


def reset_simulation():
    global messages, message_ids, keys, DH
    messages = []
    message_ids = itertools.count(1)
    keys = {"alice": make_keypair(), "bob": make_keypair()}

    # Diffie-Hellman ditampilkan sebagai demonstrasi terpisah.
    p, g, a, b = 23, 5, 6, 15
    A = pow(g, a, p)
    B = pow(g, b, p)
    DH = {
        "p": p, "g": g, "a": a, "b": b,
        "A": A, "B": B,
        "secretAlice": pow(B, a, p),
        "secretBob": pow(A, b, p)
    }


def encrypt_text(text, receiver):
    """ElGamal per byte UTF-8. Trace disimpan untuk panel edukasi."""
    public = keys[receiver]["public"]
    byte_values = list(text.encode("utf-8"))
    ciphertext = []
    trace = []
    for m in byte_values:
        k = secrets.randbelow(P - 3) + 2
        c1 = pow(G, k, P)
        c2 = (m * pow(public, k, P)) % P
        ciphertext.append([c1, c2])
        trace.append({"m": m, "k": k, "c1": c1, "c2": c2})
    return ciphertext, trace


def decrypt_text(ciphertext, receiver):
    private = keys[receiver]["private"]
    byte_values = []
    for pair in ciphertext:
        c1, c2 = int(pair[0]), int(pair[1])
        shared = pow(c1, private, P)
        m = (c2 * pow(shared, -1, P)) % P
        if not 0 <= m <= 255:
            raise ValueError("Byte hasil dekripsi tidak valid.")
        byte_values.append(m)
    return bytes(byte_values).decode("utf-8")


@app.get("/")
def index():
    return render_template("index.html")


@app.get("/api/state")
def state():
    # Jangan kirim private key melalui endpoint state.
    safe_messages = [{
        "id": m["id"], "sender": m["sender"], "receiver": m["receiver"],
        "plaintext": m["plaintext"], "ciphertext": m["ciphertext"],
        "decrypted": m["decrypted"]
    } for m in messages]
    return jsonify({
        "messages": safe_messages,
        "keys": {side: {"public": keys[side]["public"]} for side in keys},
        "dh": DH
    })


@app.post("/api/send")
def send():
    data = request.get_json(silent=True) or {}
    sender = data.get("sender")
    text = data.get("text", "")
    if sender not in ("alice", "bob"):
        return jsonify(error="Pengirim tidak valid."), 400
    if not isinstance(text, str) or not text.strip():
        return jsonify(error="Pesan tidak boleh kosong."), 400
    if len(text) > 500:
        return jsonify(error="Pesan maksimal 500 karakter."), 400

    receiver = "bob" if sender == "alice" else "alice"
    ciphertext, trace = encrypt_text(text, receiver)
    messages.append({
        "id": next(message_ids), "sender": sender, "receiver": receiver,
        "plaintext": text, "ciphertext": ciphertext, "trace": trace,
        "decrypted": False
    })
    return jsonify(ok=True)


@app.post("/api/messages/<int:message_id>/decrypt")
def decrypt(message_id):
    message = next((m for m in messages if m["id"] == message_id), None)
    if not message:
        return jsonify(error="Pesan tidak ditemukan."), 404
    # Hanya penerima pesan yang boleh menjalankan aksi dekripsi pada demo ini.
    try:
        plaintext = decrypt_text(message["ciphertext"], message["receiver"])
    except (ValueError, UnicodeDecodeError):
        return jsonify(error="Pesan gagal didekripsi."), 400
    message["plaintext"] = plaintext
    message["decrypted"] = True
    return jsonify(ok=True, plaintext=plaintext)


@app.get("/api/messages/<int:message_id>/details")
def details(message_id):
    message = next((m for m in messages if m["id"] == message_id), None)
    if not message:
        return jsonify(error="Pesan tidak ditemukan."), 404
    receiver = message["receiver"]
    return jsonify({
        "id": message["id"],
        "sender": message["sender"],
        "receiver": receiver,
        "plaintext": message["plaintext"],
        "ciphertext": message["ciphertext"],
        "trace": message["trace"],
        "p": P, "g": G,
        "privateKey": keys[receiver]["private"],
        "publicKey": keys[receiver]["public"]
    })


@app.post("/api/reset")
def reset():
    reset_simulation()
    return jsonify(ok=True)


reset_simulation()

if __name__ == "__main__":
    # Jalankan hanya di komputer sendiri untuk demo kelas.
    app.run(debug=True)
