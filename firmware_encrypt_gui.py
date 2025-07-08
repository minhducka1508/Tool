import tkinter as tk
from tkinter import filedialog, messagebox
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
import struct
import zlib
import os
import hashlib
from PIL import Image, ImageTk

# ---------- CẤU HÌNH CỨNG ----------
KEY = bytes.fromhex('603deb1015ca71be2b73aef0857d7781')

# ---------- TÍNH IV ĐỘNG TỪ HEADER ----------
def generate_iv_from_header(header_bytes: bytes) -> bytes:
    hash_full = hashlib.sha256(header_bytes).digest()
    return hash_full[:16]  # 128-bit đầu làm IV

# ---------- MÃ HÓA FIRMWARE ----------
def encrypt_firmware(input_path, output_path, firmware_type, firmware_version):
    with open(input_path, "rb") as f:
        firmware_data = f.read()

    firmware_size = len(firmware_data)
    checksum = zlib.crc32(firmware_data) & 0xFFFFFFFF

    # Header gồm: type, size, version, checksum
    header = struct.pack("<IIII", firmware_type, firmware_size, firmware_version, checksum)

    # IV động từ header
    iv = generate_iv_from_header(header)

    # Ghép header + firmware rồi mã hóa
    plaintext = header + firmware_data
    padded = pad(plaintext, 16)

    cipher = AES.new(KEY, AES.MODE_CBC, iv)
    ciphertext = cipher.encrypt(padded)

    # Ghi ra file: header gốc + ciphertext
    with open(output_path, "wb") as f:
        f.write(header)
        f.write(ciphertext)

    return firmware_size, checksum

# ---------- GIAO DIỆN GUI ----------
def browse_input():
    path = filedialog.askopenfilename(filetypes=[("Binary files", "*.bin")])
    if path:
        entry_input.delete(0, tk.END)
        entry_input.insert(0, path)

def browse_output():
    path = filedialog.asksaveasfilename(defaultextension=".bin", filetypes=[("Binary files", "*.bin")])
    if path:
        entry_output.delete(0, tk.END)
        entry_output.insert(0, path)

def run_encrypt():
    input_path = entry_input.get()
    output_path = entry_output.get()
    try:
        fw_type = int(entry_type.get(), 16)
        fw_ver = int(entry_version.get(), 16)
    except ValueError:
        messagebox.showerror("Lỗi", "Giá trị Type và Version phải ở định dạng hex (VD: 0xA5A5A5A5)")
        return

    if not os.path.isfile(input_path):
        messagebox.showerror("Lỗi", "Đường dẫn firmware không tồn tại.")
        return

    try:
        size, crc = encrypt_firmware(input_path, output_path, fw_type, fw_ver)
        messagebox.showinfo("Thành công",
            f"✅ Đã mã hóa firmware thành công!\n"
            f"Kích thước: {size} byte\nCRC32: {hex(crc)}\n\nFile: {output_path}"
        )
    except Exception as e:
        messagebox.showerror("Lỗi", f"Xảy ra lỗi khi mã hóa: {e}")

# ---------- KHỞI TẠO GUI ----------
root = tk.Tk()
root.title("Firmware Encrypt Tool")
root.geometry("600x300")
root.resizable(False, False)

tk.Label(root, text="Firmware input (.bin):").grid(row=0, column=0, sticky="e", padx=10, pady=10)
entry_input = tk.Entry(root, width=50)
entry_input.grid(row=0, column=1)
tk.Button(root, text="Browse", command=browse_input).grid(row=0, column=2, padx=5)

tk.Label(root, text="Output file:").grid(row=1, column=0, sticky="e", padx=10)
entry_output = tk.Entry(root, width=50)
entry_output.grid(row=1, column=1)
tk.Button(root, text="Browse", command=browse_output).grid(row=1, column=2, padx=5)

tk.Label(root, text="Firmware Type (hex):").grid(row=2, column=0, sticky="e", padx=10)
entry_type = tk.Entry(root, width=20)
entry_type.insert(0, "0xA5A5A5A5")
entry_type.grid(row=2, column=1, sticky="w")

tk.Label(root, text="Firmware Version (hex):").grid(row=3, column=0, sticky="e", padx=10)
entry_version = tk.Entry(root, width=20)
entry_version.insert(0, "0x031A001D")
entry_version.grid(row=3, column=1, sticky="w")

tk.Button(root, text="Mã hóa", width=20, command=run_encrypt, bg="green", fg="white").grid(row=4, column=1, pady=20)

# --- THÊM ẢNH LOGO ---
try:
    img_width, img_height = 58, 84
    logo_img = Image.open("D:/BKHN/STM32/Tool/logodhbk.png")
    try:
        resample = Image.Resampling.LANCZOS
    except AttributeError:
        resample = Image.LANCZOS
    logo_img = logo_img.resize((img_width, img_height), resample)

    logo_photo = ImageTk.PhotoImage(logo_img)
    logo_label = tk.Label(root, image=logo_photo)
    logo_label.image = logo_photo
    logo_label.place(x=600 - img_width - 10, y=300 - img_height - 10)

except Exception as e:
    print(f"Lỗi tải ảnh logo: {e}")

root.mainloop()
