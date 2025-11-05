#!/usr/bin/env python3
"""
stego_hybrid_gui_metrics.py
Versão aprimorada com métricas adicionais:
- SSIM (Structural Similarity Index)
- Entropia da imagem
Além de:
- Criptografia Híbrida AES + Blowfish
- Esteganografia LSB
- Geração e comparação de histogramas
- Interface Tkinter

Dependências:
pip install pycryptodome opencv-python numpy pillow matplotlib scikit-image scipy
"""

import os
import struct
import tkinter as tk
from tkinter import filedialog, messagebox
from PIL import Image, ImageTk
import numpy as np
import cv2
import matplotlib.pyplot as plt
from Crypto.Cipher import AES, Blowfish
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes
from skimage.metrics import structural_similarity as ssim
from scipy.stats import entropy

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
    if len(bits) % 8 != 0:
        bits += '0' * (8 - (len(bits) % 8))
    return bytes(int(bits[i:i+8], 2) for i in range(0, len(bits), 8))

# -------------------------
# IO robusta para imagens
# -------------------------
def imread_robust(path):
    try:
        arr = np.fromfile(path, dtype=np.uint8)
        img = cv2.imdecode(arr, cv2.IMREAD_COLOR)
        return img
    except Exception:
        return None

def imwrite_robust(path, img):
    ext = os.path.splitext(path)[1].lower()
    if ext == '':
        ext = '.png'
        path = path + ext
    success, enc = cv2.imencode(ext, img)
    if not success:
        raise IOError("Falha ao codificar imagem para escrita.")
    with open(path, 'wb') as f:
        enc.tofile(f)
    return path

# -------------------------
# LSB (embed / extract)
# -------------------------
def embed_message_lsb(image_path: str, message_bytes: bytes, output_path: str):
    img = imread_robust(image_path)
    if img is None:
        raise FileNotFoundError(f"Não foi possível abrir a imagem: {image_path}")

    flat = img.flatten()
    bits = bytes_to_bits(message_bytes)
    if len(bits) > flat.size:
        raise ValueError(f"Mensagem muito grande para essa imagem. capacidade_bits={flat.size}, necessário_bits={len(bits)}")

    for i, bit in enumerate(bits):
        flat[i] = (flat[i] & 254) | int(bit)

    stego = flat.reshape(img.shape)
    imwrite_robust(output_path, stego)
    return output_path

def extract_message_lsb_auto(stego_path: str):
    img = imread_robust(stego_path)
    if img is None:
        raise FileNotFoundError(f"Não foi possível abrir a imagem: {stego_path}")

    flat = img.flatten()
    header_bits = ''.join(str(int(flat[i] & 1)) for i in range(32))
    header_bytes = bits_to_bytes(header_bits)
    c_len = struct.unpack(">I", header_bytes)[0]
    total_bytes = 4 + 16 + 16 + 16 + 8 + c_len
    total_bits = total_bytes * 8
    if total_bits > flat.size:
        raise ValueError("Imagem não contém payload completo ou capacidade insuficiente.")
    bits = ''.join(str(int(flat[i] & 1)) for i in range(total_bits))
    payload = bits_to_bytes(bits)
    return payload

# -------------------------
# Métricas: PSNR, MSE, SSIM, Entropia
# -------------------------
def calculate_metrics(original_path, stego_path):
    orig = imread_robust(original_path)
    steg = imread_robust(stego_path)
    if orig is None or steg is None:
        raise FileNotFoundError("Erro ao abrir imagem para cálculo de métricas.")

    mse = np.mean((orig.astype(np.float64) - steg.astype(np.float64)) ** 2)
    psnr = float('inf') if mse == 0 else 20 * np.log10(255.0 / np.sqrt(mse))
    gray_orig = cv2.cvtColor(orig, cv2.COLOR_BGR2GRAY)
    gray_steg = cv2.cvtColor(steg, cv2.COLOR_BGR2GRAY)
    ssim_val = ssim(gray_orig, gray_steg)

    def image_entropy(image):
        hist, _ = np.histogram(image.flatten(), bins=256, range=(0, 256))
        hist = hist / np.sum(hist)
        return entropy(hist, base=2)

    entropy_orig = image_entropy(gray_orig)
    entropy_steg = image_entropy(gray_steg)

    return psnr, mse, ssim_val, entropy_orig, entropy_steg

# -------------------------
# Histograma comparativo
# -------------------------
def plot_histograms(original_path, stego_path, output_path="hist_comparison.png"):
    orig = imread_robust(original_path)
    steg = imread_robust(stego_path)
    colors = ('b', 'g', 'r')
    plt.figure(figsize=(10, 6))
    for i, col in enumerate(colors):
        hist_orig = cv2.calcHist([orig], [i], None, [256], [0, 256])
        hist_steg = cv2.calcHist([steg], [i], None, [256], [0, 256])
        plt.plot(hist_orig, color=col, linestyle='--', label=f'Original {col.upper()}')
        plt.plot(hist_steg, color=col, label=f'Estego {col.upper()}')
    plt.title("Comparação de Histogramas (Original vs Estego)")
    plt.xlabel("Intensidade (0–255)")
    plt.ylabel("Frequência de pixels")
    plt.legend()
    plt.grid(True)
    plt.tight_layout()
    plt.savefig(output_path)
    plt.close()
    return output_path

# -------------------------
# GUI (Tkinter)
# -------------------------
class StegoApp:
    def __init__(self, root):
        self.root = root
        self.root.title("🔐 AES + Blowfish + LSB (com Métricas e Histograma)")
        self.root.geometry("820x700")
        self.root.resizable(False, False)
        self.image_path = None
        self.stego_path = "stego_output.png"
        self.build_ui()

    def build_ui(self):
        tk.Label(self.root, text="Criptografia Híbrida (AES + Blowfish) + LSB", font=("Arial", 16, "bold")).pack(pady=8)
        btn_frame = tk.Frame(self.root)
        btn_frame.pack(pady=6)
        tk.Button(btn_frame, text="📂 Escolher Imagem", width=18, command=self.choose_image, bg="#2e86de", fg="white").grid(row=0, column=0, padx=6)
        tk.Button(btn_frame, text="🔒 Esconder Mensagem", width=18, command=self.encrypt_and_hide, bg="#27ae60", fg="white").grid(row=0, column=1, padx=6)
        tk.Button(btn_frame, text="🔓 Revelar Mensagem", width=18, command=self.extract_and_decrypt, bg="#c0392b", fg="white").grid(row=0, column=2, padx=6)
        tk.Button(btn_frame, text="📊 Gerar Histograma", width=18, command=self.generate_histogram, bg="#f39c12", fg="white").grid(row=0, column=3, padx=6)
        tk.Button(btn_frame, text="📈 Calcular Métricas", width=18, command=self.calculate_and_log_metrics, bg="#8e44ad", fg="white").grid(row=0, column=4, padx=6)

        self.img_label = tk.Label(self.root, text="Nenhuma imagem selecionada", font=("Arial", 11))
        self.img_label.pack()
        self.img_preview = tk.Label(self.root)
        self.img_preview.pack(pady=8)
        tk.Label(self.root, text="Mensagem secreta:", font=("Arial", 12)).pack()
        self.msg_entry = tk.Text(self.root, width=80, height=6)
        self.msg_entry.pack(pady=6)
        tk.Label(self.root, text="Log / Saída:", font=("Arial", 12)).pack(pady=(10,0))
        self.log_box = tk.Text(self.root, width=100, height=12, state="disabled", bg="#f7f7f7")
        self.log_box.pack(padx=10, pady=6)

    def choose_image(self):
        path = filedialog.askopenfilename(title="Escolha uma imagem", filetypes=[("Imagens", "*.png *.bmp *.jpg *.jpeg")])
        if not path:
            return
        self.image_path = os.path.abspath(path)
        self.img_label.config(text=os.path.basename(self.image_path))
        pil_img = Image.open(self.image_path)
        pil_img.thumbnail((300, 300))
        tk_img = ImageTk.PhotoImage(pil_img)
        self.img_preview.config(image=tk_img)
        self.img_preview.image = tk_img
        self.log(f"[OK] Imagem carregada: {self.image_path}")

    def encrypt_and_hide(self):
        if not self.image_path:
            messagebox.showerror("Erro", "Selecione uma imagem primeiro.")
            return
        message = self.msg_entry.get("1.0", tk.END).strip()
        if not message:
            messagebox.showerror("Erro", "Digite uma mensagem para esconder.")
            return
        enc = hybrid_encrypt(message)
        payload = (struct.pack(">I", len(enc["ciphertext"])) +
                   enc["aes_key"] + enc["aes_iv"] +
                   enc["blow_key"] + enc["blow_iv"] +
                   enc["ciphertext"])
        embed_message_lsb(self.image_path, payload, self.stego_path)
        messagebox.showinfo("Sucesso", f"Mensagem escondida com sucesso!\nArquivo: {self.stego_path}")
        self.log(f"[OK] Mensagem escondida em: {self.stego_path}")

    def extract_and_decrypt(self):
        if not os.path.exists(self.stego_path):
            messagebox.showerror("Erro", f"Arquivo {self.stego_path} não encontrado.")
            return
        payload = extract_message_lsb_auto(self.stego_path)
        idx = 0
        c_len = struct.unpack(">I", payload[idx:idx+4])[0]; idx += 4
        aes_key = payload[idx:idx+16]; idx += 16
        aes_iv = payload[idx:idx+16]; idx += 16
        blow_key = payload[idx:idx+16]; idx += 16
        blow_iv = payload[idx:idx+8]; idx += 8
        ciphertext = payload[idx:idx+c_len]
        data = {"aes_key": aes_key, "aes_iv": aes_iv, "blow_key": blow_key, "blow_iv": blow_iv, "ciphertext": ciphertext}
        msg = hybrid_decrypt(data)
        messagebox.showinfo("Mensagem Recuperada", msg)
        self.log(f"[OK] Mensagem recuperada: {msg}")

    def generate_histogram(self):
        if not self.image_path or not os.path.exists(self.stego_path):
            messagebox.showerror("Erro", "Gere uma imagem estego primeiro.")
            return
        out_path = plot_histograms(self.image_path, self.stego_path)
        Image.open(out_path).show()
        self.log(f"[OK] Histograma salvo em: {out_path}")

    def calculate_and_log_metrics(self):
        try:
            psnr, mse, ssim_val, ent_orig, ent_steg = calculate_metrics(self.image_path, self.stego_path)
            self.log(f"[MÉTRICAS] PSNR: {psnr:.4f} dB | MSE: {mse:.6f} | SSIM: {ssim_val:.6f}")
            self.log(f"[ENTROPIA] Original: {ent_orig:.4f} bits | Estego: {ent_steg:.4f} bits")
            messagebox.showinfo("Métricas Calculadas", f"PSNR: {psnr:.2f} dB\nMSE: {mse:.6f}\nSSIM: {ssim_val:.6f}\nEntropia (Orig): {ent_orig:.4f}\nEntropia (Estego): {ent_steg:.4f}")
        except Exception as e:
            self.log(f"[ERRO] Falha ao calcular métricas: {e}")
            messagebox.showerror("Erro", f"Falha ao calcular métricas: {e}")

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
