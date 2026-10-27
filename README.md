# Laporan Tugas Kriptografi
## Studi Kasus Pengiriman Pesan Rahasia Asya & Raissa (Diffie-Hellman & ElGamal)

### Kelompok 4
1. Tasya Aulia Darmawan (5027241009)
2. Azaria Raissa Maulidinnisa (5027241043)
3. Afriza Tristan Calendra Rajasa (5027241104)

---

## 1. Deskripsi Program
Aplikasi ini adalah web app Flask yang mengimplementasikan satu rangkaian sistem keamanan komunikasi end-to-end antara Asya dan Raissa. Seluruh operasi kriptografi (eksponensiasi modular, pembangkitan kunci, enkripsi, dan dekripsi) ditulis sendiri tanpa library kriptografi.

Library yang dipakai hanya untuk keperluan non-kriptografi:
- **`Flask`**: web server dan routing.
- **`secrets`** (modul standar Python): pembangkit bilangan acak.
- **`itertools`** (modul standar Python): penghitung ID pesan.

---

## 2. Parameter yang Digunakan
| Parameter | Nilai | Alasan |
|---|---|---|
| `p` | 65537 | Bilangan prima (2^16 + 1). Harus lebih besar dari 255 karena tiap byte pesan (0-255) dienkripsi sebagai satu angka mod p. |
| `g` | 3 | Primitive root mod 65537, sehingga g^x mod p menjangkau seluruh nilai 1..p-1. Divalidasi otomatis saat server dijalankan. |
| Kunci privat `a`, `b`, dan `k` | Acak 2..p-2 | Menghindari nilai lemah 0, 1, dan p-1. |

> **Batasan:** nilai p sekecil ini hanya untuk demo pembelajaran dan bisa dipecahkan dengan brute force. Sistem nyata memakai p minimal 2048 bit.

---

## 3. Integrasi Sistem (Alur Kerja)
Ketiga tahap dipadukan dalam satu rangkaian:

- **Tahap 1 (Diffie-Hellman):** Asya dan Raissa menyepakati bilangan prima `p` dan generator `g`. Asya memilih rahasia `a`, Raissa memilih rahasia `b`. Keduanya menghitung kunci publik dengan fungsi eksponensiasi modular buatan sendiri (`mod_exp`, metode square-and-multiply), lalu saling menukarkannya lewat jaringan publik:
  - `A = g^a mod p` (kunci publik Asya)
  - `B = g^b mod p` (kunci publik Raissa)
  - Shared secret: `B^a mod p = A^b mod p`
- **Tahap 2 (ElGamal Enkripsi):** Asya memakai kunci publik Raissa (`B`, hasil pertukaran Diffie-Hellman) untuk mengenkripsi pesan. Pesan dipecah menjadi nilai byte (integer 0-255), lalu tiap byte `m` dienkripsi dengan bilangan acak `k` baru menjadi pasangan ciphertext `(c1, c2)`:
  - `c1 = g^k mod p`
  - `c2 = m * B^k mod p`
- **Tahap 3 (ElGamal Dekripsi):** Raissa memulihkan pesan dengan kunci privat `b` yang hanya dimilikinya. Persamaan dekripsi disederhanakan tanpa inversi modular:
  - `m = c2 * c1^(p-1-b) mod p`

  Dasarnya Teorema Fermat kecil (`c1^(p-1) = 1`), sehingga `c1^(p-1-b)` sama dengan invers dari `c1^b`.

**Catatan:** karena `k` baru dipilih untuk setiap byte, pesan yang sama menghasilkan ciphertext yang berbeda setiap kali dikirim, tetapi hasil dekripsinya tetap sama.

---

## 4. Fitur Aplikasi
- Dua ruang chat (Asya dan Raissa) dengan pesan dua arah.
- Penerima melihat ciphertext terlebih dahulu, lalu mendekripsinya secara manual lewat tombol **Dekripsi**.
- Panel **Detail & Rumus** menampilkan nilai `m`, `k`, `c1`, `c2` untuk setiap byte.
- Panel Diffie-Hellman menampilkan `p`, `g`, `A`, `B`, dan shared secret.
- Tombol **Reset** membuat kunci dan pertukaran DH yang baru.

---

## 5. Struktur Proyek
```text
.
├── app.py              # backend Flask + seluruh logika DH dan ElGamal
├── requirements.txt    # dependensi
├── templates/
│   └── index.html      # halaman utama
└── static/
    ├── style.css       # tampilan
    └── script.js       # logika frontend
```

---

## 6. Cara Menjalankan Aplikasi
Prasyarat: Python 3.9 atau lebih baru.

1. Masuk ke folder proyek, lalu buat virtual environment:

```bash
python3 -m venv .venv
source .venv/bin/activate      # Windows: .venv\Scripts\activate
```

2. Instal dependensi:

```bash
pip install -r requirements.txt
```

3. Jalankan program:

```bash
python app.py
```

4. Buka browser pada alamat:

```text
http://127.0.0.1:5000/
```

> Pengguna macOS: jika port 5000 bentrok dengan AirPlay Receiver, ubah baris terakhir `app.py` menjadi `app.run(debug=True, port=5001)` lalu buka `http://127.0.0.1:5001/`.

---

## 7. Batasan
- Parameter `p` kecil, hanya untuk edukasi.
- Panel edukasi menampilkan kunci privat dan nilai `k`. Pada sistem nyata, keduanya tidak boleh diperlihatkan.
- Simulasi berjalan lokal pada satu server, bukan komunikasi jaringan sungguhan.