# İstemci-Sunucu Mimarisinde Kriptografik Uygulamalar

Bu proje, modern ve klasik şifreleme algoritmalarının çalışma mantığını **İstemci-Sunucu (Client-Server)** mimarisi üzerinde uygulamalı olarak gösteren, web tabanlı bir eğitim platformudur.

Proje, gerçek dünyadaki güvenli iletişim protokollerine (örn. HTTPS/TLS) benzer şekilde, **Hibrit Kriptosistem** (Asimetrik + Simetrik Şifreleme) yaklaşımını simüle eder.

![Ana Arayüz](screenshots/arayüz.png)


##  Projenin Amacı

* **Eğitim:** Caesar, Vigenère gibi klasik yöntemlerden, AES, RSA gibi modern standartlara kadar 15'ten fazla algoritmanın görsel olarak anlaşılmasını sağlamak.
* **Hibrit Yapı:** RSA kullanılarak güvenli anahtar değişiminin (Key Exchange) nasıl yapıldığını ve verinin AES gibi hızlı algoritmalarla nasıl şifrelendiğini göstermek.
* **Ağ Analizi Simülasyonu:** Şifreli verilerin ağ üzerinde nasıl "okunamaz" (ciphertext) halde seyahat ettiğini, entegre "Wireshark Gözlem Noktası" paneli ile görselleştirmek.

##  Özellikler

* **Çift Katmanlı Mimari:** Python Flask tabanlı ayrı çalışan Sunucu (Server) ve İstemci (Client) uygulamaları.
* **Geniş Algoritma Kütüphanesi:**
    * **Modern:** AES-128, DES, RSA.
    * **Klasik/Yer Değiştirme:** Caesar, Vigenère, Affine, Atbash, ROT13.
    * **Matematiksel/Matris:** Hill Cipher, Polybius Square.
    * **Taşıma (Transposition):** Rail Fence, Columnar Transposition, Route Cipher.
    * **Diğer:** One-Time Pad (OTP), Morse Code, Pigpen.
* **Strategy Design Pattern:** Tüm algoritmalar, SOLID prensiplerine uygun olarak `CryptoStrategy` arayüzü üzerinden modüler bir şekilde uygulanmıştır.
* **Modern Arayüz:** Tailwind CSS ile geliştirilmiş, duyarlı (responsive) ve kullanıcı dostu karanlık mod arayüzü.
* **Gerçek Zamanlı Simülasyon:** İstemcide şifrelenen verinin sunucuya gönderilmesi ve sunucuda çözülmesi (decryption) anlık olarak loglanır.

##  Ekran Görüntüleri

### Kriptoloji Kontrol Paneli ve Wireshark Çıktısı
Kullanıcı bir yöntem seçer, mesaj ve anahtar girer. Sistem, veriyi şifreler ve sunucuya iletmek üzere paketler. Alt kısımdaki panel, ağ trafiğindeki şifreli veriyi simüle eder.


(screenshots/Aesşifreleme.png)
(screenshots/Hillşifreleme.png)
(screenshots/arayüz.png)

## Kullanılan Teknolojiler

* **Backend:** Python 3.x, Flask (Web Framework)
* **Kriptografi:** `pycryptodome` (AES, DES, RSA için), `numpy` (Hill Cipher matris işlemleri için)
* **Frontend:** HTML5, JavaScript (Fetch API), Tailwind CSS (CDN)
* **İletişim:** HTTP RESTful API

