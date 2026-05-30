"""
====================================================================
  APLIKASI PENGECEKAN INTEGRITAS FILE — MD5 & SHA-256
  Versi GUI (Tkinter)
====================================================================
"""

import hashlib
import os
import tkinter as tk
from tkinter import ttk, filedialog, messagebox, scrolledtext
import datetime


# ─────────────────────────────────────────────
#  FUNGSI HASHING
# ─────────────────────────────────────────────

def hitung_hash(filepath: str, algoritma: str) -> str:
    h = hashlib.new(algoritma)
    with open(filepath, "rb") as f:
        for chunk in iter(lambda: f.read(8192), b""):
            h.update(chunk)
    return h.hexdigest()


def hitung_md5(filepath: str) -> str:
    return hitung_hash(filepath, "md5")


def hitung_sha256(filepath: str) -> str:
    return hitung_hash(filepath, "sha256")


# ─────────────────────────────────────────────
#  TEKS ANALISIS
# ─────────────────────────────────────────────

ANALISIS_MD5 = """MENGAPA MD5 TIDAK LAGI DIREKOMENDASIKAN
════════════════════════════════════════

1. RENTAN COLLISION ATTACK
   MD5 menghasilkan digest 128-bit. Pada tahun 2004, Xiaoyun Wang
   membuktikan bahwa collision (dua input berbeda menghasilkan hash
   sama) dapat ditemukan secara komputasional. Penyerang dapat
   menciptakan file palsu dengan hash MD5 yang identik dengan file asli.

2. SERANGAN PREIMAGE YANG LEBIH MUDAH
   Ukuran output 128-bit membuat brute-force lebih layak dilakukan
   dengan hardware modern (GPU / ASIC).

3. FLAME MALWARE (2012)
   Malware Flame mengeksploitasi kelemahan collision MD5 untuk
   memalsukan sertifikat digital Microsoft — membuktikan bahwa
   kelemahan MD5 bukan sekadar teori.

4. TIDAK ADA RESISTANSI SECOND PREIMAGE YANG MEMADAI
   Karena collision mudah dibuat, properti second-preimage resistance
   pun ikut melemah.

5. DILARANG OLEH STANDAR KEAMANAN
   NIST, RFC 6151, PCI-DSS, dan FIPS sudah melarang MD5 untuk
   keperluan kriptografi seperti tanda tangan digital dan
   penyimpanan kata sandi.

✖ KESIMPULAN: MD5 hanya boleh digunakan untuk checksum non-kritis,
  BUKAN untuk keperluan keamanan.
"""

ANALISIS_SHA256 = """KEUNGGULAN SHA-256
══════════════════

1. OUTPUT 256-BIT
   Ruang hash 2²⁵⁶ membuatnya secara praktis kebal terhadap
   brute-force. Menemukan collision acak membutuhkan ~2¹²⁸ operasi.

2. TIDAK ADA COLLISION YANG DIKETAHUI
   Hingga saat ini belum ada collision SHA-256 yang berhasil
   ditemukan. NIST telah menganalisis SHA-2 secara ekstensif.

3. DISTANDARISASI DAN DIAUDIT SECARA LUAS
   SHA-256 adalah bagian dari standar FIPS 180-4 dan digunakan
   dalam TLS, Bitcoin, certificate signing, dan code signing.

4. AVALANCHE EFFECT YANG KUAT
   Perubahan satu bit pada input mengubah ~50% bit output secara
   acak — hash terlihat sama sekali berbeda meski perubahan kecil.

5. RESISTENSI TERHADAP LENGTH EXTENSION ATTACK
   Lebih kuat dari MD5; dapat diamankan lebih lanjut dengan
   HMAC-SHA-256.

6. PERFORMA MEMADAI
   Dengan instruksi SHA-NI pada CPU modern, SHA-256 dapat
   diproses sangat cepat (>1 GB/s).

✔ KESIMPULAN: SHA-256 adalah pilihan standar industri yang aman
  untuk verifikasi integritas file dan aplikasi kriptografi.
"""


# ─────────────────────────────────────────────
#  KELAS APLIKASI GUI
# ─────────────────────────────────────────────

class FileIntegrityApp:
    def __init__(self, root: tk.Tk):
        self.root = root
        self.root.title("Pengecekan Integritas File — MD5 & SHA-256")
        self.root.geometry("900x680")
        self.root.resizable(True, True)
        self.root.configure(bg="#1e1e2e")

        # Warna tema
        self.CLR_BG      = "#1e1e2e"
        self.CLR_PANEL   = "#2a2a3e"
        self.CLR_ACCENT  = "#7c3aed"
        self.CLR_SUCCESS = "#22c55e"
        self.CLR_DANGER  = "#ef4444"
        self.CLR_TEXT    = "#e2e8f0"
        self.CLR_MUTED   = "#94a3b8"
        self.CLR_BORDER  = "#3f3f5a"
        self.CLR_INPUT   = "#16213e"

        self._buat_ui()

    # ── UI ──────────────────────────────────

    def _buat_ui(self):
        # Header
        header = tk.Frame(self.root, bg=self.CLR_ACCENT, height=60)
        header.pack(fill="x")
        header.pack_propagate(False)
        tk.Label(
            header,
            text="🔐  PENGECEKAN INTEGRITAS FILE  —  MD5 & SHA-256",
            font=("Segoe UI", 14, "bold"),
            bg=self.CLR_ACCENT, fg="white"
        ).pack(expand=True)

        # Notebook (tab)
        style = ttk.Style()
        style.theme_use("clam")
        style.configure("TNotebook", background=self.CLR_BG, borderwidth=0)
        style.configure("TNotebook.Tab",
                        background=self.CLR_PANEL, foreground=self.CLR_MUTED,
                        padding=[16, 8], font=("Segoe UI", 10, "bold"))
        style.map("TNotebook.Tab",
                  background=[("selected", self.CLR_ACCENT)],
                  foreground=[("selected", "white")])

        nb = ttk.Notebook(self.root)
        nb.pack(fill="both", expand=True, padx=10, pady=10)

        # Tab 1: Hitung Hash
        tab1 = tk.Frame(nb, bg=self.CLR_BG)
        nb.add(tab1, text="  📄 Hitung Hash  ")
        self._tab_hash(tab1)

        # Tab 2: Bandingkan File
        tab2 = tk.Frame(nb, bg=self.CLR_BG)
        nb.add(tab2, text="  ⚖️  Bandingkan File  ")
        self._tab_bandingkan(tab2)

        # Tab 3: Simulasi
        tab3 = tk.Frame(nb, bg=self.CLR_BG)
        nb.add(tab3, text="  🧪 Simulasi  ")
        self._tab_simulasi(tab3)

        # Tab 4: Analisis
        tab4 = tk.Frame(nb, bg=self.CLR_BG)
        nb.add(tab4, text="  📊 Analisis  ")
        self._tab_analisis(tab4)

    # ── TAB 1: HITUNG HASH ──────────────────

    def _tab_hash(self, parent):
        frame = tk.Frame(parent, bg=self.CLR_BG)
        frame.pack(fill="both", expand=True, padx=20, pady=20)

        tk.Label(frame, text="Pilih File untuk Dihitung Hash-nya",
                 font=("Segoe UI", 11, "bold"),
                 bg=self.CLR_BG, fg=self.CLR_TEXT).pack(anchor="w")

        # File picker
        row = tk.Frame(frame, bg=self.CLR_BG)
        row.pack(fill="x", pady=(8, 16))

        self.entry_file = tk.Entry(row, font=("Consolas", 10),
                                   bg=self.CLR_INPUT, fg=self.CLR_TEXT,
                                   insertbackground=self.CLR_TEXT,
                                   relief="flat", bd=6)
        self.entry_file.pack(side="left", fill="x", expand=True)

        tk.Button(row, text="📂 Browse",
                  font=("Segoe UI", 10, "bold"),
                  bg=self.CLR_ACCENT, fg="white", relief="flat",
                  padx=14, pady=6, cursor="hand2",
                  command=self._pilih_file_hash
                  ).pack(side="left", padx=(8, 0))

        tk.Button(frame, text="⚡  Hitung Hash",
                  font=("Segoe UI", 11, "bold"),
                  bg=self.CLR_SUCCESS, fg="white", relief="flat",
                  padx=20, pady=8, cursor="hand2",
                  command=self._hitung_hash_ui
                  ).pack(anchor="w")

        # Hasil
        hasil_frame = tk.Frame(frame, bg=self.CLR_PANEL,
                                bd=0, relief="flat")
        hasil_frame.pack(fill="x", pady=(16, 0))

        tk.Label(hasil_frame, text="Hasil Hash",
                 font=("Segoe UI", 10, "bold"),
                 bg=self.CLR_PANEL, fg=self.CLR_MUTED).pack(anchor="w", padx=12, pady=(10, 0))

        for label, attr in [("MD5  (128-bit)", "lbl_md5"),
                             ("SHA-256  (256-bit)", "lbl_sha256")]:
            r = tk.Frame(hasil_frame, bg=self.CLR_PANEL)
            r.pack(fill="x", padx=12, pady=4)
            tk.Label(r, text=label, width=18, anchor="w",
                     font=("Segoe UI", 10, "bold"),
                     bg=self.CLR_PANEL, fg=self.CLR_MUTED).pack(side="left")
            lbl = tk.Label(r, text="—", font=("Consolas", 10),
                           bg=self.CLR_INPUT, fg=self.CLR_TEXT,
                           anchor="w", padx=8, pady=4)
            lbl.pack(side="left", fill="x", expand=True)
            setattr(self, attr, lbl)

        # Waktu
        self.lbl_waktu_hash = tk.Label(hasil_frame, text="",
                                       font=("Segoe UI", 9),
                                       bg=self.CLR_PANEL, fg=self.CLR_MUTED)
        self.lbl_waktu_hash.pack(anchor="w", padx=12, pady=(0, 10))

    def _pilih_file_hash(self):
        path = filedialog.askopenfilename(title="Pilih File")
        if path:
            self.entry_file.delete(0, tk.END)
            self.entry_file.insert(0, path)

    def _hitung_hash_ui(self):
        path = self.entry_file.get().strip()
        if not path:
            messagebox.showwarning("Peringatan", "Pilih file terlebih dahulu!")
            return
        if not os.path.isfile(path):
            messagebox.showerror("Error", "File tidak ditemukan!")
            return
        md5    = hitung_md5(path)
        sha256 = hitung_sha256(path)
        self.lbl_md5.config(text=md5)
        self.lbl_sha256.config(text=sha256)
        self.lbl_waktu_hash.config(
            text=f"Dihitung pada: {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}"
        )

    # ── TAB 2: BANDINGKAN FILE ──────────────

    def _tab_bandingkan(self, parent):
        frame = tk.Frame(parent, bg=self.CLR_BG)
        frame.pack(fill="both", expand=True, padx=20, pady=20)

        for idx, (lbl_text, entry_attr, btn_attr) in enumerate([
            ("File Pertama (Asli)",        "entry_cmp1", "_pilih_cmp1"),
            ("File Kedua (Modifikasi)",    "entry_cmp2", "_pilih_cmp2"),
        ]):
            tk.Label(frame, text=lbl_text,
                     font=("Segoe UI", 10, "bold"),
                     bg=self.CLR_BG, fg=self.CLR_TEXT).pack(anchor="w", pady=(8 if idx else 0, 2))
            row = tk.Frame(frame, bg=self.CLR_BG)
            row.pack(fill="x", pady=(0, 4))
            entry = tk.Entry(row, font=("Consolas", 10),
                             bg=self.CLR_INPUT, fg=self.CLR_TEXT,
                             insertbackground=self.CLR_TEXT,
                             relief="flat", bd=6)
            entry.pack(side="left", fill="x", expand=True)
            setattr(self, entry_attr, entry)
            tk.Button(row, text="📂 Browse",
                      font=("Segoe UI", 10, "bold"),
                      bg=self.CLR_ACCENT, fg="white", relief="flat",
                      padx=14, pady=6, cursor="hand2",
                      command=getattr(self, btn_attr) if hasattr(self, btn_attr) else lambda: None
                      ).pack(side="left", padx=(8, 0))

        # Bind setelah widget dibuat
        children = frame.winfo_children()
        for row_frame in [c for c in children if isinstance(c, tk.Frame)]:
            for btn in [w for w in row_frame.winfo_children() if isinstance(w, tk.Button)]:
                pass  # akan di-bind setelah init

        # Ganti bind dengan lambda langsung
        frame.winfo_children()  # refresh

        # Re-bind tombol browse
        all_rows = [c for c in frame.winfo_children() if isinstance(c, tk.Frame)]
        if len(all_rows) >= 2:
            btns = [w for w in all_rows[0].winfo_children() if isinstance(w, tk.Button)]
            if btns:
                btns[0].config(command=self._pilih_cmp1)
            btns2 = [w for w in all_rows[1].winfo_children() if isinstance(w, tk.Button)]
            if btns2:
                btns2[0].config(command=self._pilih_cmp2)

        tk.Button(frame, text="⚖️   Bandingkan Sekarang",
                  font=("Segoe UI", 11, "bold"),
                  bg=self.CLR_SUCCESS, fg="white", relief="flat",
                  padx=20, pady=8, cursor="hand2",
                  command=self._bandingkan_ui
                  ).pack(anchor="w", pady=(12, 16))

        # Hasil
        self.frame_hasil_cmp = tk.Frame(frame, bg=self.CLR_PANEL)
        self.frame_hasil_cmp.pack(fill="both", expand=True)

        self.txt_cmp = scrolledtext.ScrolledText(
            self.frame_hasil_cmp,
            font=("Consolas", 10), bg=self.CLR_INPUT, fg=self.CLR_TEXT,
            insertbackground=self.CLR_TEXT, relief="flat",
            wrap="word", state="disabled"
        )
        self.txt_cmp.pack(fill="both", expand=True, padx=8, pady=8)

    def _pilih_cmp1(self):
        path = filedialog.askopenfilename(title="Pilih File Pertama")
        if path:
            self.entry_cmp1.delete(0, tk.END)
            self.entry_cmp1.insert(0, path)

    def _pilih_cmp2(self):
        path = filedialog.askopenfilename(title="Pilih File Kedua")
        if path:
            self.entry_cmp2.delete(0, tk.END)
            self.entry_cmp2.insert(0, path)

    def _bandingkan_ui(self):
        p1 = self.entry_cmp1.get().strip()
        p2 = self.entry_cmp2.get().strip()
        if not p1 or not p2:
            messagebox.showwarning("Peringatan", "Pilih kedua file terlebih dahulu!")
            return
        if not os.path.isfile(p1) or not os.path.isfile(p2):
            messagebox.showerror("Error", "Salah satu file tidak ditemukan!")
            return

        md5_1    = hitung_md5(p1)
        md5_2    = hitung_md5(p2)
        sha256_1 = hitung_sha256(p1)
        sha256_2 = hitung_sha256(p2)
        md5_sama    = md5_1 == md5_2
        sha256_sama = sha256_1 == sha256_2

        status_md5 = "✔  SAMA — File tidak berubah" if md5_sama else "✖  BERBEDA — File telah dimodifikasi!"
        status_sha = "✔  SAMA — File tidak berubah" if sha256_sama else "✖  BERBEDA — File telah dimodifikasi!"

        hasil = (
            f"{'═'*60}\n"
            f"  HASIL PERBANDINGAN FILE\n"
            f"  Waktu: {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n"
            f"{'═'*60}\n\n"
            f"  FILE 1 : {os.path.basename(p1)}\n"
            f"  FILE 2 : {os.path.basename(p2)}\n\n"
            f"{'─'*60}\n"
            f"  MD5\n"
            f"    File 1  : {md5_1}\n"
            f"    File 2  : {md5_2}\n"
            f"    Status  : {status_md5}\n\n"
            f"  SHA-256\n"
            f"    File 1  : {sha256_1}\n"
            f"    File 2  : {sha256_2}\n"
            f"    Status  : {status_sha}\n"
            f"{'─'*60}\n"
        )

        self.txt_cmp.config(state="normal")
        self.txt_cmp.delete("1.0", tk.END)
        self.txt_cmp.insert(tk.END, hasil)
        self.txt_cmp.config(state="disabled")

    # ── TAB 3: SIMULASI ─────────────────────

    def _tab_simulasi(self, parent):
        frame = tk.Frame(parent, bg=self.CLR_BG)
        frame.pack(fill="both", expand=True, padx=20, pady=20)

        tk.Label(frame,
                 text="Simulasi membuat file asli vs file yang dimodifikasi, lalu membandingkan hash-nya.",
                 font=("Segoe UI", 10), bg=self.CLR_BG, fg=self.CLR_MUTED,
                 wraplength=800, justify="left").pack(anchor="w", pady=(0, 12))

        tk.Button(frame, text="▶  Jalankan Simulasi",
                  font=("Segoe UI", 11, "bold"),
                  bg=self.CLR_ACCENT, fg="white", relief="flat",
                  padx=20, pady=8, cursor="hand2",
                  command=self._jalankan_simulasi
                  ).pack(anchor="w", pady=(0, 12))

        self.txt_sim = scrolledtext.ScrolledText(
            frame,
            font=("Consolas", 10), bg=self.CLR_INPUT, fg=self.CLR_TEXT,
            insertbackground=self.CLR_TEXT, relief="flat",
            wrap="word", state="disabled"
        )
        self.txt_sim.pack(fill="both", expand=True)

    def _jalankan_simulasi(self):
        konten_asli = (
            "Ini adalah file asli yang digunakan untuk pengujian integritas.\n"
            "Baris kedua berisi data sensitif: 1234567890\n"
            "Baris ketiga adalah informasi tambahan.\n"
            f"Tanggal pembuatan: {datetime.date.today()}\n"
        )
        konten_mod = (
            "Ini adalah file asli yang digunakan untuk pengujian integritas.\n"
            "Baris kedua berisi data sensitif: 9999999999\n"
            "Baris ketiga adalah informasi tambahan.\n"
            f"Tanggal pembuatan: {datetime.date.today()}\n"
        )

        p_asli = "sim_file_asli.txt"
        p_mod  = "sim_file_modifikasi.txt"

        with open(p_asli, "w", encoding="utf-8") as f:
            f.write(konten_asli)
        with open(p_mod, "w", encoding="utf-8") as f:
            f.write(konten_mod)

        md5_a    = hitung_md5(p_asli)
        md5_m    = hitung_md5(p_mod)
        sha256_a = hitung_sha256(p_asli)
        sha256_m = hitung_sha256(p_mod)

        for p in (p_asli, p_mod):
            if os.path.exists(p):
                os.remove(p)

        md5_sama    = md5_a == md5_m
        sha256_sama = sha256_a == sha256_m

        output = (
            f"{'═'*60}\n"
            f"  SIMULASI INTEGRITAS FILE\n"
            f"  Waktu: {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n"
            f"{'═'*60}\n\n"
            f"  ISI FILE ASLI:\n"
            f"  {'─'*50}\n"
        )
        for baris in konten_asli.splitlines():
            output += f"  {baris}\n"

        output += (
            f"\n  ISI FILE MODIFIKASI (baris ke-2 diubah):\n"
            f"  {'─'*50}\n"
        )
        for baris in konten_mod.splitlines():
            output += f"  {baris}\n"

        output += (
            f"\n{'─'*60}\n"
            f"  HASIL HASH\n"
            f"{'─'*60}\n"
            f"  MD5\n"
            f"    File asli       : {md5_a}\n"
            f"    File modifikasi : {md5_m}\n"
            f"    Status: {'✔  SAMA' if md5_sama else '✖  BERBEDA — perubahan terdeteksi!'}\n\n"
            f"  SHA-256\n"
            f"    File asli       : {sha256_a}\n"
            f"    File modifikasi : {sha256_m}\n"
            f"    Status: {'✔  SAMA' if sha256_sama else '✖  BERBEDA — perubahan terdeteksi!'}\n"
            f"{'═'*60}\n"
        )

        self.txt_sim.config(state="normal")
        self.txt_sim.delete("1.0", tk.END)
        self.txt_sim.insert(tk.END, output)
        self.txt_sim.config(state="disabled")

    # ── TAB 4: ANALISIS ─────────────────────

    def _tab_analisis(self, parent):
        frame = tk.Frame(parent, bg=self.CLR_BG)
        frame.pack(fill="both", expand=True, padx=20, pady=20)

        nb2 = ttk.Notebook(frame)
        nb2.pack(fill="both", expand=True)

        for judul, isi in [("MD5 — Kelemahan", ANALISIS_MD5),
                            ("SHA-256 — Keunggulan", ANALISIS_SHA256)]:
            tab = tk.Frame(nb2, bg=self.CLR_INPUT)
            nb2.add(tab, text=f"  {judul}  ")
            txt = scrolledtext.ScrolledText(
                tab, font=("Segoe UI", 10),
                bg=self.CLR_INPUT, fg=self.CLR_TEXT,
                insertbackground=self.CLR_TEXT,
                relief="flat", wrap="word", state="normal",
                padx=16, pady=12
            )
            txt.insert(tk.END, isi)
            txt.config(state="disabled")
            txt.pack(fill="both", expand=True)


# ─────────────────────────────────────────────
#  MAIN
# ─────────────────────────────────────────────

def main():
    root = tk.Tk()
    app = FileIntegrityApp(root)
    root.mainloop()


if __name__ == "__main__":
    main()
