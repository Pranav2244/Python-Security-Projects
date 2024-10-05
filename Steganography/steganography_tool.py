import tkinter as tk
from tkinter import filedialog, messagebox
from PIL import Image

def encode_message():
    def encode():
        message = entry.get()
        if not message:
            messagebox.showerror("Error", "Message cannot be empty")
            return

        filepath = filedialog.askopenfilename()
        if not filepath:
            return

        try:
            img = Image.open(filepath)
            encoded_img = img.copy()
            encoded_img = encode_image(encoded_img, message)
            save_path = filedialog.asksaveasfilename(defaultextension=".png")
            if save_path:
                encoded_img.save(save_path)
                messagebox.showinfo("Success", "Message encoded and image saved successfully")
        except Exception as e:
            messagebox.showerror("Error", str(e))

    encode_window = tk.Toplevel(root)
    encode_window.title("Encode Message")

    tk.Label(encode_window, text="Enter message to encode:").pack(pady=10)
    entry = tk.Entry(encode_window, width=50)
    entry.pack(pady=10)
    tk.Button(encode_window, text="Encode", command=encode).pack(pady=10)

def decode_message():
    filepath = filedialog.askopenfilename()
    if not filepath:
        return

    try:
        img = Image.open(filepath)
        message = decode_image(img)
        messagebox.showinfo("Decoded Message", f"Decoded message: {message}")
    except Exception as e:
        messagebox.showerror("Error", str(e))

def encode_image(img, msg):
    binary_msg = ''.join([format(ord(char), '08b') for char in msg])
    binary_msg += '1111111111111110'  # Delimiter

    data = list(img.getdata())
    binary_msg_idx = 0

    for i in range(len(data)):
        pixel = list(data[i])
        for j in range(3):  # Modify the RGB values
            if binary_msg_idx < len(binary_msg):
                pixel[j] = pixel[j] & ~1 | int(binary_msg[binary_msg_idx])
                binary_msg_idx += 1
        data[i] = tuple(pixel)
    
    encoded_img = Image.new(img.mode, img.size)
    encoded_img.putdata(data)
    return encoded_img

def decode_image(img):
    binary_msg = ""
    data = list(img.getdata())
    for pixel in data:
        for value in pixel[:3]:  # Only consider RGB values
            binary_msg += str(value & 1)

    chars = [binary_msg[i:i+8] for i in range(0, len(binary_msg), 8)]
    message = ""
    for char in chars:
        if char == '11111110':  # Delimiter
            break
        message += chr(int(char, 2))
    return message

root = tk.Tk()
root.title("Steganography Tool")

frame = tk.Frame(root)
frame.pack(pady=20)

tk.Button(frame, text="Encode Message", command=encode_message).grid(row=0, column=0, padx=10)
tk.Button(frame, text="Decode Message", command=decode_message).grid(row=0, column=1, padx=10)

root.mainloop()