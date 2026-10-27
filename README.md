# Laporan Tugas Kriptografi
## Studi Kasus Pengiriman Pesan Rahasia Alice & Bob (Diffie-Hellman & ElGamal)

### Kelompok X
1. Tasya Aulia Darmawan (5027241009)
2. Azaria Raissa Maulidinnisa (5027241043)
3. Afriza Tristan Calendra Rajasa (5027241104)

---

## 1. Deskripsi Program
Aplikasi ini merupakan web app Flask murni yang mengimplementasikan satu rangkaian sistem keamanan komunikasi secara end-to-end tanpa menggunakan library kriptografi instan.

Sistem ini menjawab studi kasus pengiriman pesan rahasia "TRANSFER 500000" dari Alice ke Bob menggunakan algoritma Diffie-Hellman dan ElGamal.

---

## 2. Integrasi Sistem (Alur Kerja)
Keduanya dipadukan dalam satu rangkaian sistem:

- **Tahap 1 (Diffie-Hellman):** Alice dan Bob menyepakati bilangan prima `(p)` dan generator `(g)`. Keduanya membangkitkan kunci publik masing-masing menggunakan fungsi eksponensiasi modular buatan sendiri dan saling menukarkannya lewat jaringan publik.
- **Tahap 2 (ElGamal Enkripsi):** Alice menggunakan kunci publik milik Bob (hasil dari pertukaran Diffie-Hellman) untuk mengenkripsi pesan teks "TRANSFER 500000". Pesan dipecah menjadi nilai ASCII (integer) lalu dienkripsi karakter demi karakter menjadi deretan pasangan ciphertext `(a, b)`.
- **Tahap 3 (ElGamal Dekripsi):** Bob menerima deretan ciphertext tersebut, lalu memulihkan pesan asli menggunakan kunci privat yang hanya dimilikinya. Persamaan dekripsi disederhanakan tanpa inversi menjadi `M = b * a^(p-1-x) mod p`.

---

## 3. Cara Menjalankan Aplikasi (Local Environment Win/WSL)
1. Buka terminal atau command prompt (rekomendasi menggunakan `py` atau `python3` di Windows, atau jalankan melalui WSL Ubuntu).
2. Instal dependensi:

```bash
pip install Flask
```

3. Jalankan program:

```bash
python app.py
```

4. Buka browser pada alamat berikut:

```text
http://127.0.0.1:5000/
```
