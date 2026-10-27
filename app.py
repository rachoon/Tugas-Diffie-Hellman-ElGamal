from flask import Flask, render_template, request, jsonify
import secrets      # pembangkit angka acak (modul standar Python, bukan library kriptografi)
import itertools    # penghitung ID pesan otomatis

app = Flask(__name__)

# ============================================================
# PARAMETER PUBLIK (disepakati Asya & Raissa, boleh diketahui siapa saja)
# P = 65537 : bilangan prima Fermat (2^16 + 1). Harus > 255 agar tiap byte
#             pesan (0-255) muat sebagai angka di dalam Z_P.
# G = 3     : primitive root (generator) mod P, jadi G^x mod P menjangkau
#             seluruh nilai 1..P-1. Divalidasi otomatis di bawah.
# Nilai sekecil ini HANYA untuk demo; sistem nyata memakai P >= 2048 bit.
# ============================================================
P = 65537
G = 3

message_ids = itertools.count(1)  # penghasil ID pesan: 1, 2, 3, ...
messages = []                     # semua pesan yang pernah dikirim
keys = {}                         # {"asya": {"private","public"}, "raissa": {...}}
DH = {}                           # data panel Diffie-Hellman untuk ditampilkan


# ============================================================
# FUNGSI MATEMATIKA BUATAN SENDIRI (tanpa pow() tiga argumen)
# ============================================================

def mod_exp(base, exp, mod):
    """Eksponensiasi modular: menghitung base^exp mod mod.
    Memakai metode square-and-multiply: baca bit exp dari kanan ke kiri,
    kuadratkan base di tiap langkah, dan kalikan ke hasil bila bit = 1.
    Cukup O(log exp) langkah, jadi tidak perlu menghitung base^exp penuh."""
    result = 1
    base %= mod
    while exp > 0:
        if exp & 1:                      # bit terendah = 1 -> ikut dikalikan
            result = (result * base) % mod
        base = (base * base) % mod       # kuadratkan untuk bit berikutnya
        exp >>= 1                        # geser ke bit selanjutnya
    return result


def is_prime(n):
    """Cek bilangan prima dengan pembagian coba-coba sampai akar n."""
    if n < 2:
        return False
    i = 2
    while i * i <= n:
        if n % i == 0:
            return False
        i += 1
    return True


def prime_factors(n):
    """Mengembalikan himpunan faktor prima dari n (dipakai untuk cek generator)."""
    factors = set()
    d = 2
    while d * d <= n:
        while n % d == 0:
            factors.add(d)
            n //= d
        d += 1
    if n > 1:
        factors.add(n)
    return factors


def is_generator(g, p):
    """Cek apakah g adalah primitive root mod p.
    g generator bila untuk setiap faktor prima q dari (p-1),
    g^((p-1)/q) mod p tidak sama dengan 1 (ordenya benar-benar p-1)."""
    return all(mod_exp(g, (p - 1) // q, p) != 1 for q in prime_factors(p - 1))


def random_private(p):
    """Bilangan acak 2..p-2 untuk kunci privat atau nilai acak k.
    Menghindari 0, 1, dan p-1 yang lemah/trivial."""
    return secrets.randbelow(p - 3) + 2


# Validasi parameter saat server dinyalakan: berhenti bila salah.
assert is_prime(P), "P harus bilangan prima"
assert is_generator(G, P), "G harus primitive root mod P"


# ============================================================
# TAHAP 1: DIFFIE-HELLMAN
# ============================================================

def reset_simulation():
    """Mengosongkan pesan, mereset ID, lalu menjalankan pertukaran
    Diffie-Hellman baru antara Asya dan Raissa.

    1. Keduanya sepakat memakai P dan G (publik).
    2. Asya memilih rahasia a, Raissa memilih rahasia b.
    3. Nilai publik: A = G^a mod P dan B = G^b mod P, saling ditukar.
    4. Shared secret: Asya hitung B^a, Raissa hitung A^b (hasilnya sama).

    INTEGRASI: pasangan (a, A) dan (b, B) ini juga dipakai sebagai kunci
    ElGamal. Kunci publik ElGamal y = G^x mod P identik dengan nilai publik
    DH, jadi kunci publik yang dipakai mengenkripsi adalah hasil pertukaran DH."""
    global messages, message_ids, keys, DH
    messages = []
    message_ids = itertools.count(1)

    a = random_private(P)        # rahasia Asya
    b = random_private(P)        # rahasia Raissa
    A = mod_exp(G, a, P)         # nilai publik Asya
    B = mod_exp(G, b, P)         # nilai publik Raissa

    # Kunci ElGamal = pasangan kunci hasil DH (satu sumber untuk kedua tahap).
    keys = {
        "asya": {"private": a, "public": A},
        "raissa":   {"private": b, "public": B},
    }
    DH = {
        "p": P, "g": G, "a": a, "b": b,
        "A": A, "B": B,
        "secretAsya": mod_exp(B, a, P),   # Asya: B^a mod P
        "secretRaissa":   mod_exp(A, b, P),   # Raissa: A^b mod P (sama)
    }


# ============================================================
# TAHAP 2 & 3: ELGAMAL (ENKRIPSI DAN DEKRIPSI)
# ============================================================

def encrypt_text(text, receiver):
    """Tahap 2 - Enkripsi ElGamal per byte UTF-8 dengan kunci PUBLIK penerima.
    Untuk tiap byte m dipilih k acak, lalu:
        c1 = G^k mod P
        c2 = m * y^k mod P        (y = kunci publik penerima)
    Mengembalikan (ciphertext, trace). trace menyimpan m, k, c1, c2 untuk
    panel edukasi."""
    public = keys[receiver]["public"]
    byte_values = list(text.encode("utf-8"))   # teks -> angka 0-255
    ciphertext = []
    trace = []
    for m in byte_values:
        k = random_private(P)                  # k baru tiap byte
        c1 = mod_exp(G, k, P)
        c2 = (m * mod_exp(public, k, P)) % P
        ciphertext.append([c1, c2])
        trace.append({"m": m, "k": k, "c1": c1, "c2": c2})
    return ciphertext, trace


def decrypt_text(ciphertext, receiver):
    """Tahap 3 - Dekripsi ElGamal dengan kunci PRIVAT penerima, TANPA inversi:
        m = c2 * c1^(P-1-x) mod P
    Dasarnya Teorema Fermat kecil: c1^(P-1) = 1, sehingga
    c1^(P-1-x) = (c1^x)^(-1). Jadi c2 * c1^(P-1-x) = m * y^k * g^(-kx) = m.
    Tiap byte hasil harus 0-255, lalu digabung dan di-decode jadi teks UTF-8."""
    private = keys[receiver]["private"]
    byte_values = []
    for pair in ciphertext:
        c1, c2 = int(pair[0]), int(pair[1])
        m = (c2 * mod_exp(c1, P - 1 - private, P)) % P
        if not 0 <= m <= 255:      # di luar rentang byte = kunci salah / data rusak
            raise ValueError("Byte hasil dekripsi tidak valid.")
        byte_values.append(m)
    return bytes(byte_values).decode("utf-8")


# ============================================================
# ENDPOINT FLASK
# ============================================================

@app.get("/")
def index():
    """Menampilkan halaman utama (templates/index.html)."""
    return render_template("index.html")


@app.get("/api/state")
def state():
    """Mengirim kondisi aplikasi ke frontend: pesan, kunci PUBLIK, dan data DH.
    Kunci privat ElGamal tidak dikirim di sini. Dict DH masih memuat a dan b
    karena panel DH menampilkannya untuk tujuan edukasi."""
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
    """Menerima pesan dari pengirim, memvalidasi, mengenkripsi dengan kunci
    publik penerima, lalu menyimpannya (status belum didekripsi)."""
    data = request.get_json(silent=True) or {}
    sender = data.get("sender")
    text = data.get("text", "")
    if sender not in ("asya", "raissa"):
        return jsonify(error="Pengirim tidak valid."), 400
    if not isinstance(text, str) or not text.strip():
        return jsonify(error="Pesan tidak boleh kosong."), 400
    if len(text) > 500:
        return jsonify(error="Pesan maksimal 500 karakter."), 400

    receiver = "raissa" if sender == "asya" else "asya"
    ciphertext, trace = encrypt_text(text, receiver)
    messages.append({
        "id": next(message_ids), "sender": sender, "receiver": receiver,
        "plaintext": text, "ciphertext": ciphertext, "trace": trace,
        "decrypted": False
    })
    return jsonify(ok=True)


@app.post("/api/messages/<int:message_id>/decrypt")
def decrypt(message_id):
    """Dekripsi manual saat penerima menekan tombol Dekripsi.
    Server tidak memeriksa siapa pemanggilnya (cukup untuk demo lokal)."""
    message = next((m for m in messages if m["id"] == message_id), None)
    if not message:
        return jsonify(error="Pesan tidak ditemukan."), 404
    try:
        plaintext = decrypt_text(message["ciphertext"], message["receiver"])
    except (ValueError, UnicodeDecodeError):
        return jsonify(error="Pesan gagal didekripsi."), 400
    message["plaintext"] = plaintext
    message["decrypted"] = True
    return jsonify(ok=True, plaintext=plaintext)


@app.get("/api/messages/<int:message_id>/details")
def details(message_id):
    """Rincian satu pesan untuk panel edukasi (p, g, kunci, trace per byte).
    Mengirim kunci privat penerima: HANYA untuk demo, jangan di sistem nyata."""
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
    """Tombol Reset: mulai simulasi baru (DH baru, kunci baru, pesan kosong)."""
    reset_simulation()
    return jsonify(ok=True)


reset_simulation()  # jalankan DH pertama kali saat server menyala

if __name__ == "__main__":
    # Jalankan hanya di komputer sendiri untuk demo kelas.
    app.run(debug=True)