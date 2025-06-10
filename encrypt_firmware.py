from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
import struct
import zlib

# ---------- CẤU HÌNH ----------
key = bytes.fromhex('603deb1015ca71be2b73aef0857d7781')
iv = bytes.fromhex('000102030405060708090a0b0c0d0e0f')

firmware_type = 0xA5A5A5A5
firmware_version = 0x031A001B

input_path = r"D:\BKHN\STM32\TEST_UART\Debug\TEST_UART.bin"
output_path = r"D:\BKHN\STM32\TEST_UART\Debug\TEST_UART_encrypted.bin"

# ---------- ĐỌC FIRMWARE ----------
with open(input_path, "rb") as f:
    firmware_data = f.read()

firmware_size = len(firmware_data)
# Tính CRC chỉ trên firmware, không tính metadata
checksum = zlib.crc32(firmware_data) & 0xFFFFFFFF

# ---------- TẠO METADATA RÕ RÀNG (HEADER) ----------
sha256_dummy = bytes(32)       # placeholder
signature_dummy = bytes(64)    # placeholder
active_app_flag = 0xFFFFFFFF   # bootloader sẽ ghi giá trị thật sau

# struct FirmwareMetadata_t layout:
# typedef struct {
#     uint32_t firmwareType;
#     uint32_t firmwareSize;
#     uint32_t firmwareVersion;
#     uint32_t checksumValue;
#     uint8_t  sha256[32];
#     uint8_t  signature[64];
#     uint32_t activeAppFlag;
# }

header = struct.pack("<IIII", firmware_type, firmware_size, firmware_version, checksum)
header += sha256_dummy
header += signature_dummy
header += struct.pack("<I", active_app_flag)

# ---------- TẠO METADATA CHO PHẦN MÃ HÓA ----------
# metadata mã hóa phải giống header nhưng giá trị active_app_flag có thể khác nếu cần
metadata_for_encrypt = header

# ---------- TẠO DỮ LIỆU MÃ HÓA: [metadata mã hóa] + [firmware] ----------
plaintext = metadata_for_encrypt + firmware_data

# padding chuẩn PKCS7 để dữ liệu đủ bội của 16 bytes
padded_plaintext = pad(plaintext, 16)

cipher = AES.new(key, AES.MODE_CBC, iv)
ciphertext = cipher.encrypt(padded_plaintext)

# ---------- GHI FILE RA: [metadata rõ ràng] + [dữ liệu mã hóa] ----------
with open(output_path, "wb") as f:
    f.write(header)       # metadata rõ ràng không mã hóa
    f.write(ciphertext)   # metadata mã hóa + firmware mã hóa

print(f"✅ Đã tạo firmware mã hóa thành công:\n→ {output_path}")
