import tkinter as tk
from tkinter import messagebox
import random
import string
import pyperclip

class PasswordGeneratorApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Advanced Password Generator")
        self.create_widgets()

    def create_widgets(self):
        # Title
        tk.Label(self.root, text="Random Password Generator", font=("Arial", 16, "bold")).grid(row=0, column=0, columnspan=2, pady=10)

        # Password Length
        tk.Label(self.root, text="Password Length:").grid(row=1, column=0, sticky=tk.W, padx=5)
        self.length_var = tk.IntVar(value=12)
        tk.Entry(self.root, textvariable=self.length_var, width=5).grid(row=1, column=1, padx=5, pady=5)

        # Checkbox Options
        self.include_uppercase = tk.BooleanVar(value=True)
        self.include_lowercase = tk.BooleanVar(value=True)
        self.include_numbers = tk.BooleanVar(value=True)
        self.include_symbols = tk.BooleanVar(value=True)

        tk.Checkbutton(self.root, text="Include Uppercase Letters", variable=self.include_uppercase).grid(row=2, column=0, columnspan=2, sticky=tk.W, padx=5)
        tk.Checkbutton(self.root, text="Include Lowercase Letters", variable=self.include_lowercase).grid(row=3, column=0, columnspan=2, sticky=tk.W, padx=5)
        tk.Checkbutton(self.root, text="Include Numbers", variable=self.include_numbers).grid(row=4, column=0, columnspan=2, sticky=tk.W, padx=5)
        tk.Checkbutton(self.root, text="Include Symbols", variable=self.include_symbols).grid(row=5, column=0, columnspan=2, sticky=tk.W, padx=5)

        # Generate Button
        tk.Button(self.root, text="Generate Password", command=self.generate_password).grid(row=6, column=0, columnspan=2, pady=10)

        # Output Field
        self.password_output = tk.Entry(self.root, width=30, font=("Arial", 12))
        self.password_output.grid(row=7, column=0, columnspan=2, pady=5)

        # Copy Button
        tk.Button(self.root, text="Copy to Clipboard", command=self.copy_to_clipboard).grid(row=8, column=0, columnspan=2, pady=5)

    def generate_password(self):
        length = self.length_var.get()

        if length <= 0:
            messagebox.showerror("Error", "Password length must be greater than 0.")
            return

        character_pool = ""
        if self.include_uppercase.get():
            character_pool += string.ascii_uppercase
        if self.include_lowercase.get():
            character_pool += string.ascii_lowercase
        if self.include_numbers.get():
            character_pool += string.digits
        if self.include_symbols.get():
            character_pool += string.punctuation

        if not character_pool:
            messagebox.showerror("Error", "Please select at least one character type.")
            return

        password = "".join(random.choice(character_pool) for _ in range(length))
        self.password_output.delete(0, tk.END)
        self.password_output.insert(0, password)

    def copy_to_clipboard(self):
        password = self.password_output.get()
        if password:
            pyperclip.copy(password)
            messagebox.showinfo("Success", "Password copied to clipboard!")
        else:
            messagebox.showwarning("Warning", "No password to copy.")

if __name__ == "__main__":
    root = tk.Tk()
    app = PasswordGeneratorApp(root)
    root.mainloop()
