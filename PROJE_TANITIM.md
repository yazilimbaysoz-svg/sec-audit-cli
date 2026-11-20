# sec-audit-cli - Sosyal Medya Tanitim Paketi

Hedef: Gelistiriciler, DevSecOps muhendisleri ve siber guvenlik uzmanlari.
Format: 9 slaytlik carousel + Reels/senaryo + viral aciklama.
Ton: Kisa, teknik, iddiali ama abartisiz. Marka: Baysoz Yazilim.

---

## 1. Carousel Senaryosu (9 slayt)

Ortak tasarim: 1080x1350 px, koyu lacivert (#0B1120) zemin, turkuaz (#00D4FF) vurgu,
kirmizi (#FF4D6D) risk rengi, monospace terminal kutulari, ustte kucuk "BAYSOZ YAZILIM" logosu,
altta slayt numarasi (01/09).

### Slayt 1 - Hook
- Buyuk baslik: "Tek komutta 3 guvenlik kontrolu."
- Alt baslik: "Gizli anahtar + zafiyetli paket + OWASP riski."
- Gorsel: Terminal penceresi, icinde `sec-audit .` komutu imlec yanip sonerken.
- Ust kucuk etiket: "ACIK KAYNAK / UV + PYTHON 3.11+"

### Slayt 2 - Problem
- Baslik: "Bir API anahtari depoya girdiyse, geri donusu yoktur."
- 3 madde:
  - `.env` dosyasi commit edildi
  - `requirements.txt` 2 yillik bir CVE tasiyor
  - Kodda `eval(` var, kimse fark etmedi
- Gorsel: Uc kirmizi uyari karti, yaninda buyuk "?" ikonu.

### Slayt 3 - Cozum
- Baslik: "sec-audit-cli"
- Alt baslik: "Tarar. Puanlar. Rapor verir. CI'i durdurur."
- Gorsel: Ustte logo yazisi, altta uc ikon: anahtar / kutu / kalkan (cizgi ikon).

### Slayt 4 - Ozellik 1: Secret avi
- Baslik: "Gizli anahtarlari yakalar, kendi de sizdirmiyor."
- Icerik: AWS, GitHub, OpenAI, Stripe, Slack, Google, JWT, PEM + entropi analizi.
- Ornek bulgu satiri: `SEC-OAI-001  CRITICAL  config.py:12`
- Alt not: "Cikti: sk-**************** [sha256:1a2b3c4d]"

### Slayt 5 - Ozellik 2: Bagimliliklar
- Baslik: "9 formattan zafiyet okur."
- Icerik: requirements, pyproject, package.json, package-lock, yarn.lock, Cargo.lock, go.mod, Pipfile.lock.
- Ornek: `DEP-CVE-2023-32681  requests 2.30.0 -> 2.31.0`
- Kucuk etiket: "OPSIYONEL OSV API MODU"

### Slayt 6 - Ozellik 3: OWASP
- Baslik: "Kodunuzdaki 12 tehlikeli kalibi bilir."
- Icerik: SQLi, command injection, XSS, SSRF, path traversal, weak hash, XXE, debug mode ...
- Ornek: `OWASP-A03-CMDI  subprocess.run(shell=True)`

### Slayt 7 - Hiz ve CI
- Baslik: "85 milisaniye. 0 bağımlılık. 1 komut."
- Gorsel: Sol panel terminal, sag panel JSON.
- Kod: `sec-audit . --fail-on high --output rapor.json`
- Alt not: "Cikis kodu 1 = pipeline durur."

### Slayt 8 - Kurulum
- Baslik: "30 saniyede calistirin."
- Terminal satirlari:
  - `git clone https://github.com/yazilimbaysoz-svg/sec-audit-cli`
  - `cd sec-audit-cli && uv venv && uv pip install -e .`
  - `sec-audit .`
- Vurgu: "Python 3.11+, sifir runtime bagimliligi."

### Slayt 9 - CTA
- Baslik: "Deponuza bugun tarama ekleyin."
- Alt baslik: "GitHub'da yildizlayin, ekibinize gonderin."
- Gorsel: QR yerine buyuk repo adi: `github.com/yazilimbaysoz-svg/sec-audit-cli`
- Kucuk not: "MIT lisansli. 57 test, yuzde 89 kapsam, ruff + semgrep temiz."

---

## 2. Viral Aciklama Metni (Instagram)

Deponuza bir API anahtari sizdi mi? Fark etmeniz 3 saniye, fark etmemeniz 3 ay surer.

sec-audit-cli tam olarak burada devreye giriyor: tek komutla gizli anahtarlari,
zafiyetli paketleri ve OWASP risklerini tarayan acik kaynak bir guvenlik CLI'si.

Ne yapiyor?
- AWS, GitHub, OpenAI, Stripe, Slack, Google ve JWT anahtarlarini yakaliyor
- 9 farkli manifest formatinda bilinen CVE'leri buluyor
- SQL injection'dan XXE'ye 12 OWASP kalibini isaretliyor
- Buldugu siri maskeliyor, rapora sadece SHA-256 parmak izi koyuyor
- 85 milisaniyede renkli terminal ve JSON raporu uretiyor
--fail-on high ile CI pipeline'inizi otomatik durduruyor

Kurulum: git clone, uv venv, uv pip install -e . ve `sec-audit .` kadar kolay.
57 birim testi, yuzde 89 test kapsami, ruff ve semgrep denetimlerinden gecmis durumda.

Siz de ekibinize bir guvenlik kontrolu eklemek isterseniz repo baglantisi biyografide.
Yildizlamak ve paylasmak bizi bir sonraki araca tasir.

#siberGuvenlik #devsecops #acikkaynak #python #github #developerTools #owasp #appsec #guvenlik #yazilim

---

## 3. Reels / Shorts Senaryosu (20 saniye)

| Sure | Gorsel | Ses / Metin |
|---|---|---|
| 0-3 sn | Siyah ekranda kirmizi "API KEY LEAKED" yazisi | "Bir API anahtari depoya girdi." |
| 3-6 sn | Terminal acilir, `sec-audit .` yazilir | "Tek komut." |
| 6-11 sn | Kirmizi CRITICAL satirlari akar | "Gizli anahtar, CVE ve OWASP riski tek taramada." |
| 11-15 sn | JSON raporu kaydirilir | "Maskeli bulgular, net remediation, makine okunabilir rapor." |
| 15-18 sn | CI ekraninda pipeline durur | "Ve gerekirse pipeline durur." |
| 18-20 sn | Logo + repo adi | "Acik kaynak: sec-audit-cli." |

---

## 4. Story Dizisi (4 adim)

1. Anket: "Deponuzda gizli anahtar taramasi var mi?" Evet / Hayir
2. Ekran goruntusu: CRITICAL bulgulu terminal cikti + "Bunu yakalayan komut"
3. Kaydirma: Kurulumun 3 satiri + "Sizin deponuzda deneyin"
4. Baglanti etiketi: GitHub repo + "Yildizlayin, bir sonraki araci birlikte sectirelim"

---

## 5. Paylasim Oncesi Kontrol

- [ ] Terminal ekran goruntusunde gercek sira/dosya adi yok
- [ ] Secilen ornek bulgular yapay verilerden uretildi
- [ ] README ve LICENSE repo icinde
- [ ] GitHub repo linki biyografi ve son slayta eklendi
- [ ] Etiketler Turkce + Ingilizce karisim, 8-10 adet
