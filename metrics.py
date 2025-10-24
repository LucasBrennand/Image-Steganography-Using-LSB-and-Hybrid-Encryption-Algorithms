import cv2
import numpy as np

def psnr_mse(original_path, stego_path):
    original = cv2.imread(original_path)
    stego = cv2.imread(stego_path)
    mse = np.mean((original - stego) ** 2)
    if mse == 0:
        psnr = float('inf')
    else:
        psnr = 20 * np.log10(255.0 / np.sqrt(mse))
    return psnr, mse

if __name__ == "__main__":
    psnr, mse = psnr_mse("demo_output/original_demo.png", "demo_output/stego_demo.png")
    print(f"PSNR = {psnr:.2f} dB")
    print(f"MSE = {mse:.8f}")
