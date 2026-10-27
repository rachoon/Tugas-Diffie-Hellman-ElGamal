// Pintasan untuk document.querySelector, supaya pemanggilan elemen lebih singkat.
const $ = (selector) => document.querySelector(selector);

// Menyimpan kondisi terakhir dari server: pesan, kunci publik, dan data DH.
// Seluruh tampilan digambar dari objek ini.
let appState = { messages: [], keys: {}, dh: null };

// Pemetaan id internal ke nama yang ditampilkan di UI.
const names = { asya: "Asya", raissa: "Raissa" };


/**
 * Pembungkus fetch untuk memanggil API Flask.
 * - Otomatis mengirim header JSON.
 * - Mengurai respons JSON.
 * - Jika status bukan 2xx, melempar Error berisi pesan dari server,
 *   sehingga pemanggil cukup memakai try/catch.
 */
async function api(url, options = {}) {
  const response = await fetch(url, {
    headers: { "Content-Type": "application/json" },
    ...options
  });
  const data = await response.json();
  if (!response.ok) throw new Error(data.error || "Terjadi kesalahan.");
  return data;
}


/**
 * Mengganti karakter khusus HTML (& < > " ') dengan entitasnya.
 * Wajib dipakai sebelum memasukkan teks pengguna ke innerHTML
 * agar tidak terjadi XSS (pesan berisi <script> tidak dieksekusi).
 */
function escapeHtml(value) {
  return String(value).replace(/[&<>"']/g, (char) => ({
    "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#039;"
  }[char]));
}


/**
 * Mengubah array ciphertext [[c1,c2], ...] menjadi string
 * "(c1, c2) (c1, c2) ..." agar bisa ditampilkan di gelembung chat.
 */
function ciphertextText(ciphertext) {
  return ciphertext.map(([c1, c2]) => `(${c1}, ${c2})`).join(" ");
}


/**
 * Aturan tampilan:
 *  - Pengirim selalu melihat plaintext pesannya sendiri.
 *  - Penerima melihat ciphertext sampai menekan tombol "Dekripsi".
 *  - Tombol "Dekripsi" hanya muncul di sisi penerima yang belum mendekripsi.
 *  - Tombol "Detail & Rumus" muncul di sisi penerima.
 */
function renderMessages() {
  for (const side of ["asya", "raissa"]) {
    const root = $(`#${side}Messages`);
    // Ambil hanya pesan yang melibatkan sisi ini (sebagai pengirim atau penerima).
    const relevant = appState.messages.filter(m => m.sender === side || m.receiver === side);
    if (!relevant.length) {
      // Belum ada pesan: tampilkan teks kosong lalu lanjut ke sisi berikutnya.
      root.innerHTML = `<div class="empty-state"><span class="empty-icon">✦</span>Belum ada pesan.<br>Mulai percakapan dengan mengirim pesan.</div>`;
      continue;
    }
    root.innerHTML = relevant.map(m => {
      const outgoing = m.sender === side;              // true = pesan keluar dari sisi ini
      const visiblePlaintext = outgoing || m.decrypted; // kapan plaintext boleh terlihat
      const content = visiblePlaintext
        ? escapeHtml(m.plaintext)
        : escapeHtml(ciphertextText(m.ciphertext));
      const bubbleClass = !visiblePlaintext ? "bubble cipher-bubble" : "bubble";
      const label = outgoing ? `Terkirim ke ${names[m.receiver]}` : `Dari ${names[m.sender]}`;

      // Susun tombol aksi sesuai status pesan.
      let actions = "";
      if (!outgoing && !m.decrypted) {
        actions += `<button class="small-button decrypt" data-action="decrypt" data-id="${m.id}">Dekripsi</button>`;
      }
      if (!outgoing) {
        actions += `<button class="small-button" data-action="details" data-id="${m.id}" data-side="${side}">Detail &amp; Rumus</button>`;
      }
      return `<div class="message ${outgoing ? "outgoing" : "incoming"}">
        <div class="${bubbleClass}">${content}</div>
        <div class="msg-meta">${label} · ${outgoing ? "plaintext di sisi pengirim" : (m.decrypted ? "berhasil didekripsi" : "ciphertext / terenkripsi")}</div>
        ${actions ? `<div class="msg-actions">${actions}</div>` : ""}
      </div>`;
    }).join("");
    // Gulir otomatis ke pesan terbaru.
    root.scrollTop = root.scrollHeight;
  }
}


/**
 * Menggambar panel Diffie-Hellman di bagian bawah halaman:
 * parameter publik (p, g), nilai publik A dan B, serta shared secret
 * yang dihitung masing-masing pihak (keduanya harus sama).
 */
function renderDH() {
  const d = appState.dh;
  if (!d) return; // data belum dimuat dari server
  $("#dhContent").innerHTML = `
    <div class="dh-step"><h4>Parameter publik</h4>
      <div class="formula">p = ${d.p}<br>g = ${d.g}</div>
      <p>Nilai p dan g boleh diketahui oleh siapa pun.</p></div>
    <div class="dh-step"><h4>Nilai publik Asya &amp; Raissa</h4>
      <div class="formula">A = gᵃ mod p = ${d.A}<br>B = gᵇ mod p = ${d.B}</div>
      <p>Private Asya a = ${d.a}; private Raissa b = ${d.b}. Nilai privat tidak dikirim ke lawan.</p></div>
    <div class="dh-step"><h4>Shared secret</h4>
      <div class="formula">s Asya = Bᵃ mod p = ${d.secretAsya}<br>s Raissa = Aᵇ mod p = ${d.secretRaissa}</div>
      <p>Kedua pihak memperoleh rahasia yang sama: <b>${d.secretAsya}</b>.</p></div>`;
}


/**
 * Mengambil kondisi terbaru dari server (/api/state), lalu menggambar
 * ulang pesan dan panel DH. Dipanggil setelah setiap aksi (kirim, dekripsi, reset).
 */
async function refresh() {
  appState = await api("/api/state");
  renderMessages();
  renderDH();
}


/**
 * Mengirim pesan dari `sender` ke server (/api/send).
 * Enkripsi ElGamal dilakukan di server, lalu tampilan disegarkan.
 */
async function sendMessage(sender, text) {
  await api("/api/send", { method: "POST", body: JSON.stringify({ sender, text }) });
  await refresh();
}


/**
 * Meminta server mendekripsi pesan berdasarkan id-nya
 * (memakai kunci privat penerima), lalu menyegarkan tampilan.
 */
async function decryptMessage(id) {
  await api(`/api/messages/${id}/decrypt`, { method: "POST", body: "{}" });
  await refresh();
}


/**
 * Menampilkan panel "Detail & Rumus" untuk satu pesan.
 * Panel ini MENGGANTIKAN tampilan chat di sisi penerima:
 *  1. ambil rincian dari /api/messages/<id>/details,
 *  2. susun HTML: plaintext, kunci, langkah enkripsi per byte (trace),
 *     rumus dekripsi, dan ciphertext,
 *  3. sembunyikan tampilan chat, tampilkan panel detail.
 */
async function showDetails(id, side) {
  const data = await api(`/api/messages/${id}/details`);
  const target = $(`#${side}Detail`); // wadah panel detail
  const view = $(`#${side}View`);     // wadah tampilan chat biasa

  // Satu blok per byte: m, k acak, c1, c2.
  const traces = data.trace.map((t, i) => `
    <div class="trace-row">
      Byte ${i + 1}: m = ${t.m}<br>
      k acak = ${t.k}<br>
      c₁ = gᵏ mod p = ${t.c1}<br>
      c₂ = m × yᵏ mod p = ${t.c2}
    </div>`).join("");

  target.innerHTML = `
    <div class="detail-top"><div><p class="eyebrow">RINCIAN PESAN</p><h3>Enkripsi &amp; dekripsi ElGamal</h3><p>${names[data.sender]} → ${names[data.receiver]}</p></div>
      <button class="small-button" data-action="back" data-side="${side}">← Kembali ke Chat</button></div>
    <div class="detail-block"><h4>1. Plaintext dan encoding</h4>
      <p>Pesan asli: <b>${escapeHtml(data.plaintext)}</b></p>
      <p>Pesan diubah menjadi byte UTF-8 agar karakter teks dapat diproses secara numerik.</p>
      <span class="detail-formula">m = byte pesan, dengan 0 ≤ m ≤ 255</span></div>
    <div class="detail-block"><h4>2. Kunci publik penerima</h4>
      <span class="detail-formula">p = ${data.p}, g = ${data.g}<br>x (private key penerima) = ${data.privateKey}<br>y = gˣ mod p = ${data.publicKey}</span>
      <p>Kunci publik (p, g, y) dipakai pengirim. Private key x hanya digunakan penerima untuk dekripsi.</p></div>
    <div class="detail-block"><h4>3. Proses enkripsi</h4>
      <span class="detail-formula">c₁ = gᵏ mod p<br>c₂ = m × yᵏ mod p<br>C = (c₁, c₂)</span>
      <p>Setiap byte memakai nilai acak k. Hasil pasangan ciphertext berikut diperlihatkan agar prosesnya dapat dipelajari.</p>
      <div class="trace-list">${traces}</div></div>
    <div class="detail-block"><h4>4. Proses dekripsi</h4>
      <span class="detail-formula">s = c₁ˣ mod p<br>m = c₂ × c₁^(p-1-x) mod p<br>byte → decode UTF-8 → plaintext</span>
      <p>Jika penerima menekan tombol Dekripsi, server menghitung c₁^(p-1-x) dengan Teorema Fermat kecil (tanpa invers modular) untuk mengembalikan setiap byte ke pesan asli.</p></div>
    <div class="detail-block"><h4>5. Ciphertext yang dikirim</h4>
      <span class="detail-formula">${escapeHtml(ciphertextText(data.ciphertext))}</span>
      <p>Dalam aplikasi nyata, jangan menampilkan private key atau nilai acak k seperti pada panel pembelajaran ini.</p></div>`;

  // Tukar tampilan: sembunyikan chat, tampilkan detail.
  view.classList.add("hidden");
  target.classList.remove("hidden");
}


/**
 * Kembali dari panel detail ke tampilan chat biasa pada sisi tertentu.
 */
function backToChat(side) {
  $(`#${side}Detail`).classList.add("hidden");
  $(`#${side}View`).classList.remove("hidden");
}


// ===== EVENT LISTENER =====

// Form kirim pesan (satu per sisi): cegah reload halaman, kirim pesan,
// kosongkan input, dan tampilkan error lewat alert bila gagal.
for (const side of ["asya", "raissa"]) {
  $(`#${side}Form`).addEventListener("submit", async (event) => {
    event.preventDefault();
    const input = $(`#${side}Input`);
    const text = input.value.trim();
    if (!text) return;
    try {
      await sendMessage(side, text);
      input.value = "";
      input.focus();
    } catch (error) { alert(error.message); }
  });
}

// Satu listener untuk semua tombol dinamis (event delegation).
// Tombol dibuat ulang lewat innerHTML tiap render, jadi listener dipasang
// di document dan dibaca dari atribut data-action: decrypt / details / back.
document.addEventListener("click", async (event) => {
  const button = event.target.closest("[data-action]");
  if (!button) return;
  const action = button.dataset.action;
  try {
    if (action === "decrypt") await decryptMessage(button.dataset.id);
    if (action === "details") await showDetails(button.dataset.id, button.dataset.side);
    if (action === "back") backToChat(button.dataset.side);
  } catch (error) { alert(error.message); }
});

// Tombol Reset: minta konfirmasi, reset server (kunci dan pesan baru),
// tutup semua panel detail, lalu segarkan tampilan.
$("#resetBtn").addEventListener("click", async () => {
  if (!confirm("Hapus semua pesan dan mulai ulang simulasi?")) return;
  try {
    await api("/api/reset", { method: "POST", body: "{}" });
    for (const side of ["asya", "raissa"]) backToChat(side);
    await refresh();
  } catch (error) { alert(error.message); }
});

// Pemuatan awal saat halaman dibuka. Jika backend tidak berjalan,
// tampilkan pesan error di bagian atas halaman.
refresh().catch(error => {
  document.querySelector(".page").insertAdjacentHTML("afterbegin",
    `<p class="error">Gagal terhubung ke backend: ${escapeHtml(error.message)}. Pastikan Flask sudah dijalankan.</p>`);
});