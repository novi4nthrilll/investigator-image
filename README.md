# Investigator - Cyber-Forensic Digital Image Intelligence Suite

CLI tool modular untuk analisis forensik citra digital (manipulasi gambar, anti-tampering, dan investigasi siber).

---

## 🛠️ Modul 1: Tamper & Manipulation Hunter

Modul pertama ini berfokus pada deteksi modifikasi/rekayasa gambar dengan 3 pilar uji forensik:

1. **Error Level Analysis (ELA):**
   - Mendeteksi anomali kompresi JPEG akibat proses *re-saving*, penyuntingan lokal, atau penempelan objek (*splicing*).
   - Menghitung statistik Z-score per blok spasial untuk menandai area yang dicurigai.
2. **Sensor Noise Inconsistency (Residual Variance):**
   - Mengisolasi *noise residual* frekuensi tinggi (simulasi PRNU sensor kamera).
   - Membandingkan varians noise lokal antar blok untuk mendeteksi area yang terlalu halus (hasil *smoothing/inpaint*) atau terlalu berisik (berasal dari gambar lain).
3. **Copy-Move Forgery Detection (CMFD):**
   - Mendeteksi *clone-stamp* atau duplikasi objek pada gambar yang sama dengan ekstraksi fitur blok dan pengelompokan vektor translasi (*shift-vector clustering*).
4. **Chain of Custody & Hashes:**
   - Menghitung otomatis hash kriptografis **SHA-256** dan **MD5** untuk integritas bukti investigasi.
5. **Visual Heatmap Export:**
   - Menyimpan *heatmap overlay* yang memvisualisasikan konsentrasi anomali secara grafis.

---

## 🚀 Cara Menjalankan

### 1. Bantuan / Help Menu
```bash
python3 run.py tamper --help
```

### 2. Analisis Gambar Biasa
```bash
python3 run.py tamper <path_ke_gambar>
```

### 3. Analisis dengan Export Heatmap Visual
```bash
python3 run.py tamper <path_ke_gambar> -o heatmap_result.png
```

### 4. Mode JSON (Untuk Integrasi Pipeline / SIEM)
```bash
python3 run.py tamper <path_ke_gambar> --json
```

---

## 🧪 Contoh Pengujian
Sampel pengujian telah disediakan di direktori `tests/samples/`:
```bash
# Uji gambar otentik
python3 run.py tamper tests/samples/test_clean.jpg

# Uji gambar dengan rekayasa noise & cloning
python3 run.py tamper tests/samples/test_tampered.jpg -o tests/samples/tampered_heatmap.png
```

---

## 🕵️ Modul 2: Stego & Malicious Payload Analyzer

Modul kedua berfokus pada deteksi penyembunyian data rahasia (*steganography*), file polyglot, dan penyusupan payload malware di balik file gambar:

1. **Trailing Bytes & Polyglot Detection:**
   - Memeriksa batas resmi *End-Of-File* (EOF) dari format JPEG (`FF D9`), PNG (`IEND`), dan GIF (`3B`).
   - Mendeteksi byte tambahan (*overlay*) yang diselundupkan di ekor file gambar.
   - Mengenali signature file rahasia: ZIP, RAR, 7Z, GZIP, PDF, Windows PE Executable (MZ), Linux ELF, PHP, JavaScript, dan Shell scripts.
2. **Automated Payload Carving (`-x`):**
   - Otomatis mengekstrak dan memotong (*carve*) file arsip atau script tersembunyi menjadi file mandiri yang siap dianalisis tim insiden.
3. **Least Significant Bit (LSB) & Bitplane Entropy:**
   - Menguji keacakan bitplane 0 (LSB) pada setiap channel RGB menggunakan Shannon Entropy.
   - Uji Chi-Square ($\chi^2$) *Pairs of Values* (PoV) untuk membuktikan apakah frekuensi piksel telah diratakan oleh payload stego terenkripsi.
4. **LSB Bitplane Visual Dump (`-d`):**
   - Menyimpan visualisasi biner bitplane 0 untuk inspeksi visual langsung (berguna untuk CTF atau menemukan watermark tersembunyi).
5. **EXIF & Metadata Security Auditor:**
   - Memindai komentar JPEG dan tag EXIF dari keberadaan string Base64 panjang, perintah shell (`powershell`, `cmd`, `curl`, `bash`), script injection, dan URL C2 berbasis IP.

---

### Cara Menjalankan Modul 2:

```bash
# Bantuan command stego
python3 run.py stego --help

# Pindai steganografi biasa
python3 run.py stego <path_gambar>

# Pindai dan ekstrak payload tersembunyi (carving)
python3 run.py stego <path_gambar> -x ./hasil_carving/

# Pindai sambil dump visualisasi LSB bitplane 0
python3 run.py stego <path_gambar> -d ./lsb_plane.png
```

---

## 🤖 Modul 3: AI-Generated & Deepfake Authenticator

Modul ketiga mengidentifikasi apakah sebuah gambar dibuat oleh AI generatif (Midjourney, Stable Diffusion, DALL-E, Flux, ComfyUI) atau merupakan jepretan kamera optik asli:

1. **2D FFT Frequency Magnitude Spectrum:**
   - Mentransformasi gambar ke domain frekuensi 2 dimensi menggunakan 2D Fast Fourier Transform (FFT).
   - Mendeteksi *periodic grid spikes* / lonjakan frekuensi harmonik simetris yang tercipta akibat proses *upsampling* konvolusi atau *latent patch diffusion*.
   - Mengukur deviasi kurva peluruhan radial dari hukum spektrum optik alami $1/f^\alpha$.
2. **C2PA / Content Credentials Provenance Scanner:**
   - Memeriksa struktur manifest JUMBF/C2PA digital untuk memverifikasi klaim `trainedAlgorithmicMedia` atau `c2pa.ai_generated` dari Adobe Firefly, Microsoft Designer, atau kamera tersertifikasi.
3. **Automated Generation Prompt Extractor (`-p`):**
   - Mendeteksi dan mengekstrak prompt lengkap, negative prompt, seed, model checkpoint, dan konfigurasi sampler dari chunk PNG (`parameters`, `workflow`, `prompt`) ke dalam file teks.
4. **2D FFT Spectrum Visual Dump (`-f`):**
   - Menyimpan visualisasi spektrum frekuensi 2D ke dalam file gambar untuk analisis visual para peneliti forensik.
5. **Chroma & Saturation Distribution Analysis:**
   - Mengukur konsentrasi saturasi ekstrem dan distribusi varians warna pada ruang YCbCr yang sering kali tidak wajar pada model difusi.

---

### Cara Menjalankan Modul 3:

```bash
# Bantuan command ai
python3 run.py ai --help

# Autentikasi gambar AI biasa
python3 run.py ai <path_gambar>

# Autentikasi sambil dump peta spektrum frekuensi 2D FFT
python3 run.py ai <path_gambar> -f ./fft_spectrum.png

# Autentikasi dan ekstrak prompt AI generator ke file
python3 run.py ai <path_gambar> -p ./prompt_hasil_ekstrak.txt

# Mode JSON
python3 run.py ai <path_gambar> --json
```



