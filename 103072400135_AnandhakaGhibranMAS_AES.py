"""Template praktikum: dua fitur enkripsi dan dekripsi teks menggunakan AES-GCM.

Instal dependensi: pip install cryptography
Mahasiswa mengisi bagian TODO pada fungsi enkripsi() dan dekripsi().
"""
import base64
import hashlib
import os

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.exceptions import InvalidTag


def turunkan_kunci(kata_sandi: str, salt: bytes) -> bytes:
    """Kunci 32 byte untuk AES-256 dari kata sandi dan salt."""
    return hashlib.pbkdf2_hmac(
        "sha256", kata_sandi.encode("utf-8"), salt, 200_000, dklen=32
    )


def enkripsi(teks: str, kata_sandi: str) -> str:
    """Input: dua teks. Output: satu teks ciphertext Base64."""
    # 1. Buat salt acak 16 byte dan nonce acak 12 byte
    salt = os.urandom(16)
    nonce = os.urandom(12)
    
    # 2. Buat kunci dengan turunkan_kunci()
    kunci = turunkan_kunci(kata_sandi, salt)
    
    # 3. Enkripsi teks UTF-8 menggunakan AESGCM
    aesgcm = AESGCM(kunci)
    ciphertext = aesgcm.encrypt(nonce, teks.encode("utf-8"), None)
    
    # 4. Gabungkan salt + nonce + ciphertext (termasuk auth tag)
    payload = salt + nonce + ciphertext
    
    # 5. Encode gabungan dengan Base64, lalu return sebagai string
    return base64.b64encode(payload).decode("utf-8")


def dekripsi(ciphertext_b64: str, kata_sandi: str) -> str:
    """Input: dua teks. Output: plaintext atau pesan kegagalan."""
    # 1. Decode ciphertext_b64 dari Base64 menjadi bytes
    data = base64.b64decode(ciphertext_b64.encode("utf-8"))
    
    # Validasi panjang data minimal (16 byte salt + 12 byte nonce = 28 byte)
    if len(data) < 28:
        raise ValueError("Ciphertext tidak valid.")
        
    # 2. Pisahkan salt (16 byte), nonce (12 byte), dan sisa ciphertext
    salt = data[:16]
    nonce = data[16:28]
    ciphertext = data[28:]
    
    # 3. Buat kembali kunci dengan turunkan_kunci()
    kunci = turunkan_kunci(kata_sandi, salt)
    
    # 4. Dekripsi AESGCM, lalu decode UTF-8 menjadi teks
    aesgcm = AESGCM(kunci)
    plaintext_bytes = aesgcm.decrypt(nonce, ciphertext, None)
    
    return plaintext_bytes.decode("utf-8")


def main() -> None:
    while True:
        print("\n=== ENKRIPSI SIMETRIS (AES-GCM) ===")
        print("1. Enkripsi teks")
        print("2. Dekripsi teks")
        print("0. Keluar")
        pilihan = input("Pilih menu: ").strip()
        if pilihan == "0":
            print("Program selesai.")
            break
        if pilihan not in {"1", "2"}:
            print("Pilihan menu tidak valid.")
            continue
        pesan = input("Masukkan plaintext: " if pilihan == "1" else "Masukkan ciphertext Base64: ")
        kata_sandi = input("Masukkan kata sandi: ")
        if not kata_sandi:
            print("Kata sandi tidak boleh kosong.")
            continue
        try:
            if pilihan == "1":
                print("Ciphertext (Base64):", enkripsi(pesan, kata_sandi))
            else:
                print("Plaintext:", dekripsi(pesan, kata_sandi))
        except (InvalidTag, ValueError, UnicodeDecodeError) as exc:
            print("Dekripsi gagal: kata sandi atau ciphertext tidak sesuai.")
        except NotImplementedError as exc:
            print(exc)


if __name__ == "__main__":
    main()
