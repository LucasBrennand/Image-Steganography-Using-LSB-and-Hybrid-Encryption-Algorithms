#!/usr/bin/env python3
"""
stego_hybrid_gui_fixed.py
Versão corrigida da GUI com:
- leitura/gravação robusta de imagens (suporta nomes com acentos/espacos no Windows)
- extração automática do tamanho do payload (não precisa passar length)
- AES + Blowfish + LSB
Dependências:
pip install pycryptodome opencv-python numpy pillow
"""

import os
import struct
import tkinter as tk
from tkinter import filedialog, messagebox
from PIL import Image, ImageTk
import numpy as np
import cv2
from Crypto.Cipher import AES, Blowfish
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes

# -------------------------
# Criptografia híbrida AES + Blowfish
# -------------------------
def hybrid_encrypt(message: str):
    aes_key = get_random_bytes(16)
    blow_key = get_random_bytes(16)
    aes_iv = get_random_bytes(16)
    blow_iv = get_random_bytes(8)

    aes_cipher = AES.new(aes_key, AES.MODE_CBC, aes_iv)
    aes_encrypted = aes_cipher.encrypt(pad(message.encode('utf-8'), AES.block_size))

    blow_cipher = Blowfish.new(blow_key, Blowfish.MODE_CBC, blow_iv)
    blow_encrypted = blow_cipher.encrypt(pad(aes_encrypted, Blowfish.block_size))

    return {
        "ciphertext": blow_encrypted,
        "aes_key": aes_key,
        "blow_key": blow_key,
        "aes_iv": aes_iv,
        "blow_iv": blow_iv
    }

def hybrid_decrypt(data):
    ciphertext = data["ciphertext"]
    blow_cipher = Blowfish.new(data["blow_key"], Blowfish.MODE_CBC, data["blow_iv"])
    after_blow = unpad(blow_cipher.decrypt(ciphertext), Blowfish.block_size)

    aes_cipher = AES.new(data["aes_key"], AES.MODE_CBC, data["aes_iv"])
    decrypted = unpad(aes_cipher.decrypt(after_blow), AES.block_size)
    return decrypted.decode('utf-8')

# -------------------------
# Helpers bits <-> bytes
# -------------------------
def bytes_to_bits(data: bytes) -> str:
    return ''.join(f'{b:08b}' for b in data)

def bits_to_bytes(bits: str) -> bytes:
    # pad to multiple of 8
    if len(bits) % 8 != 0:
        bits += '0' * (8 - (len(bits) % 8))
    return bytes(int(bits[i:i+8], 2) for i in range(0, len(bits), 8))

# -------------------------
# IO robusta para imagens (Windows compatível com caminhos com acentos)
# -------------------------
def imread_robust(path):
    # Retorna imagem BGR (cv2 format) ou None
    try:
        arr = np.fromfile(path, dtype=np.uint8)
        img = cv2.imdecode(arr, cv2.IMREAD_COLOR)
        return img
    except Exception:
        return None

def imwrite_robust(path, img):
    # img deve estar em formato cv2 (BGR numpy array)
    ext = os.path.splitext(path)[1].lower()
    if ext == '':
        ext = '.png'
        path = path + ext
    success, enc = cv2.imencode(ext, img)
    if not success:
        raise IOError("Falha ao codificar imagem para escrita.")
    # tofile lida melhor com nomes com acentos no Windows
    with open(path, 'wb') as f:
        enc.tofile(f)
    return path

# -------------------------
# LSB embed / extract (agora extract auto detecta payload size)
# -------------------------
def embed_message_lsb(image_path: str, message_bytes: bytes, output_path: str):
    img = imread_robust(image_path)
    if img is None:
        raise FileNotFoundError(f"Não foi possível abrir a imagem: {image_path}")

    h, w, c = img.shape
    flat = img.flatten()
    bits = bytes_to_bits(message_bytes)
    if len(bits) > flat.size:
        raise ValueError(f"Mensagem muito grande para essa imagem. capacidade_bits={flat.size}, necessário_bits={len(bits)}")

    # embed
    for i, bit in enumerate(bits):
        flat[i] = (flat[i] & 254) | int(bit)

    stego = flat.reshape(img.shape)
    imwrite_robust(output_path, stego)
    return output_path

def extract_message_lsb_auto(stego_path: str):
    """
    Extrai automaticamente o payload lendo primeiro 32 bits (4 bytes) do LSB.
    O header é: 4 bytes (big-endian) = tamanho do ciphertext (c_len)
    Mas no payload que montamos: payload = [4 c_len] + aes_key(16) + aes_iv(16) + blow_key(16) + blow_iv(8) + ciphertext(c_len)
    Precisamos ler (4 + 16 +16 +16 +8 + c_len) bytes = 60 + c_len bytes total.
    Aqui primeiro lemos 4 bytes (32 bits) para obter c_len e então lemos o total.
    Retorna bytes do payload completo.
    """
    img = imread_robust(stego_path)
    if img is None:
        raise FileNotFoundError(f"Não foi possível abrir a imagem: {stego_path}")

    flat = img.flatten()

    # Ler primeiro 32 bits -> 4 bytes para c_len
    header_bits = ''.join(str(int(flat[i] & 1)) for i in range(32))
    header_bytes = bits_to_bytes(header_bits)
    c_len = struct.unpack(">I", header_bytes)[0]

    total_bytes = 4 + 16 + 16 + 16 + 8 + c_len  # 4 + aes_key + aes_iv + blow_key + blow_iv + ciphertext
    total_bits = total_bytes * 8

    if total_bits > flat.size:
        raise ValueError("Imagem não contém payload completo ou capacidade insuficiente.")

    bits = ''.join(str(int(flat[i] & 1)) for i in range(total_bits))
    payload = bits_to_bytes(bits)
    return payload

# -------------------------
# GUI (Tkinter)
# -------------------------
class StegoApp:
    def __init__(self, root):
        self.root = root
        self.root.title("🔐 AES + Blowfish + LSB (GUI)")
        self.root.geometry("760x620")
        self.root.resizable(False, False)

        self.image_path = None
        self.enc_data = None
        self.payload_bytes = None
        self.stego_path = "stego_output.png"

        self.build_ui()

    def build_ui(self):
        tk.Label(self.root, text="Criptografia Híbrida (AES + Blowfish) + LSB", font=("Arial", 16, "bold")).pack(pady=8)

        btn_frame = tk.Frame(self.root)
        btn_frame.pack(pady=6)
        tk.Button(btn_frame, text="📂 Escolher Imagem", width=18, command=self.choose_image, bg="#2e86de", fg="white").grid(row=0, column=0, padx=6)
        tk.Button(btn_frame, text="🔒 Esconder Mensagem", width=18, command=self.encrypt_and_hide, bg="#27ae60", fg="white").grid(row=0, column=1, padx=6)
        tk.Button(btn_frame, text="🔓 Revelar Mensagem", width=18, command=self.extract_and_decrypt, bg="#c0392b", fg="white").grid(row=0, column=2, padx=6)

        self.img_label = tk.Label(self.root, text="Nenhuma imagem selecionada", font=("Arial", 11))
        self.img_label.pack()

        self.img_preview = tk.Label(self.root)
        self.img_preview.pack(pady=8)

        tk.Label(self.root, text="Mensagem secreta:", font=("Arial", 12)).pack()
        self.msg_entry = tk.Text(self.root, width=80, height=6)
        self.msg_entry.pack(pady=6)

        tk.Label(self.root, text="Log / Saída:", font=("Arial", 12)).pack(pady=(10,0))
        self.log_box = tk.Text(self.root, width=90, height=10, state="disabled", bg="#f7f7f7")
        self.log_box.pack(padx=10, pady=6)

    def choose_image(self):
        path = filedialog.askopenfilename(title="Escolha uma imagem", filetypes=[("Imagens", "*.png *.bmp *.jpg *.jpeg")])
        if not path:
            return
        # guarda caminho absoluto
        self.image_path = os.path.abspath(path)
        self.img_label.config(text=os.path.basename(self.image_path))

        # mostra miniatura
        try:
            pil_img = Image.open(self.image_path)
            pil_img.thumbnail((300, 300))
            tk_img = ImageTk.PhotoImage(pil_img)
            self.img_preview.config(image=tk_img)
            self.img_preview.image = tk_img
            self.log(f"[OK] Imagem carregada: {self.image_path}")
        except Exception as e:
            self.log(f"[ERRO] Falha ao abrir miniatura: {e}")

    def encrypt_and_hide(self):
        if not self.image_path:
            messagebox.showerror("Erro", "Selecione uma imagem primeiro.")
            return
        message = self.msg_entry.get("1.0", tk.END).strip()
        if not message:
            messagebox.showerror("Erro", "Digite uma mensagem para esconder.")
            return

        try:
            # criptografa
            self.enc_data = hybrid_encrypt(message)

            # monta payload: [4 c_len] + aes_key(16) + aes_iv(16) + blow_key(16) + blow_iv(8) + ciphertext
            payload = (
                struct.pack(">I", len(self.enc_data["ciphertext"])) +
                self.enc_data["aes_key"] + self.enc_data["aes_iv"] +
                self.enc_data["blow_key"] + self.enc_data["blow_iv"] +
                self.enc_data["ciphertext"]
            )
            self.payload_bytes = payload

            # embute
            embed_message_lsb(self.image_path, payload, self.stego_path)
            self.log(f"[OK] Mensagem escondida em: {self.stego_path} (payload {len(payload)} bytes)")
            messagebox.showinfo("Sucesso", f"Mensagem escondida com sucesso! Arquivo: {self.stego_path}")
        except Exception as e:
            self.log(f"[ERRO] Falha ao embutir: {e}")
            messagebox.showerror("Erro", f"Falha ao embutir: {e}")

    def extract_and_decrypt(self):
        if not os.path.exists(self.stego_path):
            messagebox.showerror("Erro", f"Arquivo {self.stego_path} não encontrado. Primeiro execute 'Esconder Mensagem'.")
            return

        try:
            payload = extract_message_lsb_auto(self.stego_path)
            # parse payload
            idx = 0
            c_len = struct.unpack(">I", payload[idx:idx+4])[0]; idx += 4
            aes_key = payload[idx:idx+16]; idx += 16
            aes_iv = payload[idx:idx+16]; idx += 16
            blow_key = payload[idx:idx+16]; idx += 16
            blow_iv = payload[idx:idx+8]; idx += 8
            ciphertext = payload[idx:idx+c_len]

            encdata = {
                "aes_key": aes_key,
                "aes_iv": aes_iv,
                "blow_key": blow_key,
                "blow_iv": blow_iv,
                "ciphertext": ciphertext
            }
            recovered = hybrid_decrypt(encdata)
            messagebox.showinfo("Mensagem Recuperada", recovered)
            self.log(f"[OK] Mensagem recuperada: {recovered}")
        except Exception as e:
            self.log(f"[ERRO] Falha ao extrair/decifrar: {e}")
            messagebox.showerror("Erro", f"Falha ao extrair/decifrar: {e}")

    def log(self, text):
        self.log_box.config(state="normal")
        self.log_box.insert(tk.END, text + "\n")
        self.log_box.see(tk.END)
        self.log_box.config(state="disabled")

# -------------------------
# Execução
# -------------------------
if __name__ == "__main__":
    root = tk.Tk()
    app = StegoApp(root)
    root.mainloop()
