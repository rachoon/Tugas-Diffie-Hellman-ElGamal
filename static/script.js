const $ = (selector) => document.querySelector(selector);
let appState = { messages: [], keys: {}, dh: null };
const names = { alice: "Alice", bob: "Bob" };

async function api(url, options = {}) {
  const response = await fetch(url, {
    headers: { "Content-Type": "application/json" },
    ...options
  });
  const data = await response.json();
  if (!response.ok) throw new Error(data.error || "Terjadi kesalahan.");
  return data;
}

function escapeHtml(value) {
  return String(value).replace(/[&<>"']/g, (char) => ({
    "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#039;"
  }[char]));
}

function ciphertextText(ciphertext) {
  return ciphertext.map(([c1, c2]) => `(${c1}, ${c2})`).join(" ");
}

function renderMessages() {
  for (const side of ["alice", "bob"]) {
    const root = $(`#${side}Messages`);
    const relevant = appState.messages.filter(m => m.sender === side || m.receiver === side);
    if (!relevant.length) {
      root.innerHTML = `<div class="empty-state"><span class="empty-icon">✦</span>Belum ada pesan.<br>Mulai percakapan dengan mengirim pesan.</div>`;
      continue;
    }
    root.innerHTML = relevant.map(m => {
      const outgoing = m.sender === side;
      const visiblePlaintext = outgoing || m.decrypted;
      const content = visiblePlaintext
        ? escapeHtml(m.plaintext)
        : escapeHtml(ciphertextText(m.ciphertext));
      const bubbleClass = !visiblePlaintext ? "bubble cipher-bubble" : "bubble";
      const label = outgoing ? `Terkirim ke ${names[m.receiver]}` : `Dari ${names[m.sender]}`;
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
    root.scrollTop = root.scrollHeight;
  }
}

function renderDH() {
  const d = appState.dh;
  if (!d) return;
  $("#dhContent").innerHTML = `
    <div class="dh-step"><h4>Parameter publik</h4>
      <div class="formula">p = ${d.p}<br>g = ${d.g}</div>
      <p>Nilai p dan g boleh diketahui oleh siapa pun.</p></div>
    <div class="dh-step"><h4>Nilai publik Asya &amp; Raissa</h4>
      <div class="formula">A = gᵃ mod p = ${d.A}<br>B = gᵇ mod p = ${d.B}</div>
      <p>Private Asya a = ${d.a}; private Raissa b = ${d.b}. Nilai privat tidak dikirim ke lawan.</p></div>
    <div class="dh-step"><h4>Shared secret</h4>
      <div class="formula">s Asya = Bᵃ mod p = ${d.secretAlice}<br>s Raissa = Aᵇ mod p = ${d.secretBob}</div>
      <p>Kedua pihak memperoleh rahasia yang sama: <b>${d.secretAlice}</b>.</p></div>`;
}

async function refresh() {
  appState = await api("/api/state");
  renderMessages();
  renderDH();
}

async function sendMessage(sender, text) {
  await api("/api/send", { method: "POST", body: JSON.stringify({ sender, text }) });
  await refresh();
}

async function decryptMessage(id) {
  await api(`/api/messages/${id}/decrypt`, { method: "POST", body: "{}" });
  await refresh();
}

async function showDetails(id, side) {
  const data = await api(`/api/messages/${id}/details`);
  const target = $(`#${side}Detail`);
  const view = $(`#${side}View`);
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
      <span class="detail-formula">s = c₁ˣ mod p<br>m = c₂ × s⁻¹ mod p<br>byte → decode UTF-8 → plaintext</span>
      <p>Jika penerima menekan tombol Dekripsi, server menghitung invers modular untuk mengembalikan setiap byte ke pesan asli.</p></div>
    <div class="detail-block"><h4>5. Ciphertext yang dikirim</h4>
      <span class="detail-formula">${escapeHtml(ciphertextText(data.ciphertext))}</span>
      <p>Dalam aplikasi nyata, jangan menampilkan private key atau nilai acak k seperti pada panel pembelajaran ini.</p></div>`;
  view.classList.add("hidden");
  target.classList.remove("hidden");
}

function backToChat(side) {
  $(`#${side}Detail`).classList.add("hidden");
  $(`#${side}View`).classList.remove("hidden");
}

for (const side of ["alice", "bob"]) {
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

$("#resetBtn").addEventListener("click", async () => {
  if (!confirm("Hapus semua pesan dan mulai ulang simulasi?")) return;
  try {
    await api("/api/reset", { method: "POST", body: "{}" });
    for (const side of ["alice", "bob"]) backToChat(side);
    await refresh();
  } catch (error) { alert(error.message); }
});

refresh().catch(error => {
  document.querySelector(".page").insertAdjacentHTML("afterbegin",
    `<p class="error">Gagal terhubung ke backend: ${escapeHtml(error.message)}. Pastikan Flask sudah dijalankan.</p>`);
});
