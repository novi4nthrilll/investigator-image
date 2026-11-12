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

