from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
import struct
import zlib

# ---------- CẤU HÌNH ----------
key = bytes.fromhex('603deb1015ca71be2b73aef0857d7781')
iv = bytes.fromhex('000102030405060708090a0b0c0d0e0f')

firmware_type = 0xA5A5A5A5
firmware_version = 0x031A001D

input_path = r"D:\BKHN\STM32\TEST_UART\Debug\TEST_UART.bin"
output_path = r"D:\BKHN\STM32\TEST_UART\Debug\test_uart_encrypted_2.bin"

# ---------- ĐỌC FIRMWARE ----------
with open(input_path, "rb") as f:
    firmware_data = f.read()

firmware_size = len(firmware_data)
checksum = zlib.crc32(firmware_data) & 0xFFFFFFFF

# ---------- TẠO HEADER đơn giản ----------
# typedef struct {
#     uint32_t firmwareType;
#     uint32_t firmwareSize;
#     uint32_t firmwareVersion;
#     uint32_t checksumValue;
# }
header = struct.pack("<IIII", firmware_type, firmware_size, firmware_version, checksum)

# ---------- TẠO DỮ LIỆU MÃ HÓA: [header mã hóa] + [firmware] ----------
plaintext = header + firmware_data
padded_plaintext = pad(plaintext, 16)

cipher = AES.new(key, AES.MODE_CBC, iv)
ciphertext = cipher.encrypt(padded_plaintext)

# ---------- GHI FILE RA: [header rõ ràng] + [ciphertext mã hóa] ----------
with open(output_path, "wb") as f:
    f.write(header)       # header rõ ràng để bootloader đọc trước
    f.write(ciphertext)   # phần đã mã hóa: header lặp lại + firmware

print(f"✅ Đã tạo firmware mã hóa (header đơn giản) thành công:\n→ {output_path}")
