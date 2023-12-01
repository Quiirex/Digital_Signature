import tkinter as tk
from tkinter import filedialog
import time
import hashlib
import rsa


class DigitalSigner:
    def __init__(self):
        self.private_key, self.public_key = rsa.newkeys(2048)

    def sign_file(self, file_path):
        with open(file_path, "rb") as f:
            data = f.read()
        hash = int(hashlib.sha256(data).hexdigest(), 16)
        signature = rsa.encrypt(hash.to_bytes(32), self.private_key)
        return signature

    def verify_signature(self, file_path, signature):
        with open(file_path, "rb") as f:
            data = f.read()
        hash = int(hashlib.sha256(data).hexdigest(), 16)
        try:
            decrypted_hash = int.from_bytes(rsa.decrypt(signature, self.public_key))
            return hash == decrypted_hash
        except rsa.DecryptionError:
            return False


class GUI:
    def __init__(self, root):
        self.root = root
        root.title("Digital Signature")

        print("Generating private and public key pair...")
        start = time.time()
        self.signer = DigitalSigner()
        end = time.time()
        print(f"Key pair generated. Took {round(end - start, 2)} seconds.")

        self.file_path = None
        self.signature = None

        self.input_frame = tk.Frame(root)
        self.input_frame.grid(row=0, column=0, padx=10, pady=10)

        self.text_label = tk.Label(
            self.input_frame,
            text="Input:",
            width=15,
            font=("Helvetica", 13, "bold"),
            anchor="e",
        )
        self.text_label.grid(row=0, column=0)
        self.loaded_file_label = tk.Label(
            self.input_frame, text="<No file loaded>", width=30
        )
        self.loaded_file_label.grid(row=0, column=1)

        self.status_label = tk.Label(
            self.input_frame,
            text="Signature status:",
            width=15,
            font=("Helvetica", 13, "bold"),
            anchor="e",
        )
        self.status_label.grid(row=1, column=0)
        self.status_text = tk.Label(self.input_frame, text="<No file loaded>", width=30)
        self.status_text.grid(row=1, column=1)

        self.verification_label = tk.Label(
            self.input_frame,
            text="Verification status:",
            width=15,
            font=("Helvetica", 13, "bold"),
            anchor="e",
        )
        self.verification_label.grid(row=2, column=0)
        self.verification_text = tk.Label(
            self.input_frame, text="<No file loaded>", width=30
        )
        self.verification_text.grid(row=2, column=1)

        tk.Label(
            self.input_frame,
            text="Output:",
            width=15,
            font=("Helvetica", 13, "bold"),
            anchor="e",
        ).grid(row=3, column=0, padx=10)
        self.output_text = tk.Text(self.input_frame, width=60, height=11)
        self.output_text.grid(row=3, column=1)
        self.output_text.config(state=tk.DISABLED)

        self.button_frame = tk.Frame(root)
        self.button_frame.grid(row=1, column=0, padx=10, pady=10)

        self.load_file_button = tk.Button(
            self.button_frame,
            text="Load file..",
            command=self.load_file,
            width=10,
        )
        self.load_file_button.grid(row=0, column=0)

        self.sign_button = tk.Button(
            self.button_frame,
            text="Sign File",
            command=self.sign_file,
            state=tk.DISABLED,
            width=10,
        )
        self.sign_button.grid(row=1, column=0)

        self.verify_button = tk.Button(
            self.button_frame,
            text="Verify Signature",
            command=self.verify_signature,
            state=tk.DISABLED,
            width=10,
        )
        self.verify_button.grid(row=2, column=0)

    def load_file(self):
        self.file_path = filedialog.askopenfilename(filetypes=[("All Files", "*.*")])
        if self.file_path:
            self.loaded_file_label.config(text=f'"{self.file_path.split("/")[-1]}"')
            self.status_text.config(text="Ready to sign.")
            self.output_text.delete("1.0", tk.END)
            self.verification_text.config(text="Ready to verify.")
            self.sign_button["state"] = tk.NORMAL
        else:
            self.loaded_file_label.config(text="<No file loaded>")
        print(f"File loaded: {self.file_path}")

    def sign_file(self):
        try:
            self.signature = self.signer.sign_file(self.file_path)
            self.verify_button["state"] = tk.NORMAL
            self.status_text.config(text="File signed.")
            self.output_text.config(state=tk.NORMAL)
            self.output_text.delete("1.0", tk.END)
            self.output_text.insert(tk.END, "Signature digest:\n")
            self.output_text.insert(tk.END, str(hex(int.from_bytes(self.signature))))
            self.output_text.config(state=tk.DISABLED)
            print("File signed.")
        except Exception as e:
            self.status_text.config(text=f"Error: {e}")
            print(f"Error: {e}")

    def verify_signature(self):
        try:
            is_valid = self.signer.verify_signature(self.file_path, self.signature)
            if is_valid:
                self.verification_text.config(text="Signature valid.")
                print("Signature valid.")
            else:
                self.verification_text.config(text="Signature invalid.")
                print("Signature invalid.")
        except Exception as e:
            self.verification_text.config(text=f"Error: {e}")
            print(f"Error: {e}")


if __name__ == "__main__":
    root = tk.Tk()
    gui = GUI(root)
    root.mainloop()
