# 🛡️ Personal EDR — Uç Nokta Güvenlik ve Tehdit Engelleme Sistemi

<p align="center">
  <img src="https://img.shields.io/badge/Python-3.10%2B-3776AB?logo=python&logoColor=white" alt="Python">
  <img src="https://img.shields.io/badge/Machine_Learning-Random_Forest-F7931E?logo=scikit-learn&logoColor=white" alt="Scikit-Learn">
  <img src="https://img.shields.io/badge/Framework-Flask-000000?logo=flask&logoColor=white" alt="Flask">
  <img src="https://img.shields.io/badge/OS-Windows-0078D6?logo=windows&logoColor=white" alt="Windows">
  <img src="https://img.shields.io/badge/Cybersecurity-EDR%20%7C%20Threat_Intel-red" alt="Security">
  <img src="https://img.shields.io/badge/License-MIT-green" alt="License">
</p>

> **"Kişisel bilgisayarınızı bilgi hırsızlarına, kimlik avına ve zararlı yazılımlara karşı koruyan çok katmanlı uç nokta savunma mekanizması."**  
> Personal EDR, modern uç nokta koruma prensiplerini (Endpoint Detection and Response) makine öğrenmesi destekli phishing tespiti, gerçek zamanlı tarayıcı oturum (cookie) koruması ve otomatik DNS sinkhole tehdit istihbaratı ile birleştiren modüler bir siber güvenlik yazılımıdır.

---

## 🏛️ Savunma Mimarisi & Modüller

```
                                  [ Kişisel Bilgisayar ]
                                            │
        ┌───────────────────────────────────┼───────────────────────────────────┐
        ▼                                   ▼                                   ▼
┌───────────────────────┐       ┌───────────────────────┐       ┌───────────────────────┐
│   ML Phishing Guard   │       │  Cookie Shield Engine │       │  DNS Sinkhole Filter  │
│ (Random Forest & API) │       │ (Watchdog & Process)  │       │ (Threat Intel Feeds)  │
└───────────────────────┘       └───────────────────────┘       └───────────────────────┘
        │                                   │                                   │
        ▼                                   ▼                                   ▼
Canlı URL Özellik Çıkarımı        Oturum Hırsızlığı & Redline       C2 Sunucuları & Zararlı
ve Anlık Skorlama API'si          Stealer Süreçlerini Engelleme     Domainleri Host Seviyesinde Bloklama
```

---

## ⚡ Temel Bileşenler

### 1. 🤖 Makine Öğrenmesi Destekli Phishing Dedektörü (`app.py`)
- Eğitilmiş **Random Forest Classifier** modeli (`phishing_model.joblib`) ile URL'leri 15+ sezgisel parametreye göre (entropi, alt alan adı derinliği, IP formatı, şüpheli anahtar kelimeler) analiz eder.
- Flask REST API (`POST /predict`) üzerinden hem tarayıcı eklentisine hem de yerel servislere gerçek zamanlı tehdit skoru döndürür.

### 2. 🍪 Cookie Shield — Oturum Hırsızlığı Kalkanı (`cookie_shield.py`)
- Redline, Vidar, Raccoon gibi bilgi hırsızı (infostealer) zararlı yazılımlarının hedef aldığı tarayıcı çerez veritabanlarını (`Network/Cookies`) `watchdog` ile 7/24 izler.
- Yetkisiz bir üçüncü taraf sürecin çerez dosyalarına erişimini veya kopyalama girişimini anında yakalayarak süreci sonlandırır ve loglar.

### 3. 🌐 DNS / Host Seviyesi Tehdit Sinkhole (`sinkhole.py`)
- **URLhaus Threat Intelligence** akışlarından otomatik olarak güncellenen zararlı C2 (Komuta Kontrol) ve malware dağıtım domainlerini çeker.
- Windows hosts dosyasını yedekli ve güvenli biçimde güncelleyerek bilinen tehditleri işletim sistemi seviyesinde `0.0.0.0` adresine yönlendirip etkisiz kılar.

### 4. 🧩 Tarayıcı Eklentisi & Kontrol Paneli (`extension/` & `dashboard/`)
- Kullanıcı internette gezinirken ziyaret edilen web sitelerini arka plandaki Flask motoruna soran ve şüpheli sitelerde kırmızı alarm veren hafif Chrome/Edge eklentisi.
- Güvenlik olaylarını, engellenen erişimleri ve sistem durumunu gösteren modern karanlık tema web kontrol paneli.

---

## 📂 Klasör Yapısı

```bash
personal-edr-security/
├── app.py                     # Flask API & Random Forest Phishing sınıflandırıcı
├── cookie_shield.py           # Watchdog tabanlı çerez veritabanı koruma servisi
├── sinkhole.py                # URLhaus destekli DNS/Hosts engelleme modülü
├── phishing_model.joblib      # Eğitilmiş scikit-learn model ağırlıkları
├── setup_startup.py           # Arka planda gizli başlangıç ve servis kurulum scripti
├── requirements.txt           # Python kütüphane bağımlılıkları
├── dashboard/                 # Güvenlik kontrol paneli frontend şablonları
├── extension/                 # Chrome Manifest V3 tarayıcı koruma eklentisi
└── static/                    # Dashboard stil ve görsel varlıkları
```

---

## 🚀 Kurulum ve Kullanım

### 1. Ortamın Hazırlanması

```bash
# Repoyu klonlayın
git clone https://github.com/siladgn/personal-edr-security.git
cd personal-edr-security

# Bağımlılıkları yükleyin
pip install -r requirements.txt
```

### 2. Modülleri Başlatma

```bash
# Phishing API & Kontrol Panelini başlatın:
python app.py

# Cookie Shield koruma motorunu başlatın:
python cookie_shield.py

# Tehdit istihbaratı sinkhole filtresini güncelleyin (Yönetici hakları gerektirir):
python sinkhole.py
```

### 3. Tarayıcı Eklentisini Yükleme
1. Chrome veya Edge tarayıcınızda `chrome://extensions` adresine gidin.
2. Sağ üstten **Geliştirici Modu (Developer mode)** anahtarını açın.
3. **Paketlenmemiş öğe yükle (Load unpacked)** butonuna basarak projedeki `extension/` klasörünü seçin.

---

## ⚠️ Güvenlik ve Uyarı

Bu yazılım kişisel güvenlik araştırmaları ve uç nokta savunma analizi amacıyla geliştirilmiştir. Hosts dosyasını düzenleme işlemleri işletim sisteminde yönetici (Administrator) izni gerektirir.

---

## 📄 Lisans

Bu proje [MIT](LICENSE) lisansı ile lisanslanmıştır.
