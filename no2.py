import base64
import hashlib
from Crypto.Cipher import AES

def generate_barcode(nomor_pengiriman, tanggal_kirim, kode_cabang_distributor):
    """
    Menghasilkan barcode yang merupakan enkripsi dari NomorPengiriman, TanggalKirim, dan KodeCabangDistributor

    Args:
        nomor_pengiriman: Nomor pengiriman dalam format string
        tanggal_kirim: Tanggal pengiriman dalam format string
        kode_cabang_distributor: Kode cabang distributor dalam format string

    Returns:
        Barcode dalam format string
    """

    data = f"{nomor_pengiriman}|{tanggal_kirim}|{kode_cabang_distributor}"
    sha1_hash = hashlib.sha1(data.encode()).digest()
    iv = os.urandom(AES.block_size)
    cipher = AES.new(sha1_hash, AES.MODE_OCB, iv)
    ciphertext = cipher.encrypt(data.encode())
    return base64.b64encode(ciphertext)

def main():
    nomor_pengiriman = "1234567890"
    tanggal_kirim = "2023-08-02"
    kode_cabang_distributor = "ABCD"

    barcode = generate_barcode(nomor_pengiriman, tanggal_kirim, kode_cabang_distributor)

    print(barcode)

if __name__ == "__main__":
    main()
