import tkinter as tk
from tkinter import messagebox, ttk, filedialog
import string
import random
import pyperclip

class PasswordGeneratorApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Password Generator")
        self.root.geometry("400x440")
        self.password_length_value = tk.StringVar()
        self.password_length_value.set("7")
        self.password_history = []
        self.create_widgets()

    def create_widgets(self):
        self.root.configure(bg="black")
        self.title_label = tk.Label(self.root, text="PASSWORD GENERATOR", font=("Arial", 24, "bold"), bg="black", fg="white")
        self.title_label.pack(pady=10)
        self.label_length = tk.Label(self.root, text="Password Length:", bg="black", fg="white")
        self.label_length.pack()
        self.password_length = tk.Entry(self.root, textvariable=self.password_length_value)
        self.password_length.pack()
        self.label_charset = tk.Label(self.root, text="Character Set:", bg="black", fg="white")
        self.label_charset.pack()
        self.use_lowercase = tk.BooleanVar()
        self.use_uppercase = tk.BooleanVar()
        self.use_digits = tk.BooleanVar()
        self.use_special_chars = tk.BooleanVar()
        style = ttk.Style()
        style.configure("Custom.TCheckbutton", background="black", foreground="white")
        self.check_lowercase = ttk.Checkbutton(self.root, text="Lowercase", variable=self.use_lowercase, style="Custom.TCheckbutton")
        self.check_lowercase.pack()
        self.check_uppercase = ttk.Checkbutton(self.root, text="Uppercase", variable=self.use_uppercase, style="Custom.TCheckbutton")
        self.check_uppercase.pack()
        self.check_digits = ttk.Checkbutton(self.root, text="Digits", variable=self.use_digits, style="Custom.TCheckbutton")
        self.check_digits.pack()
        self.check_special_chars = ttk.Checkbutton(self.root, text="Special Characters", variable=self.use_special_chars, style="Custom.TCheckbutton")
        self.check_special_chars.pack()
        self.use_lowercase.set(True)
        self.use_uppercase.set(True)
        self.use_digits.set(True)
        self.use_special_chars.set(True)
        self.generate_button = tk.Button(self.root, text="Generate Password", command=self.generate_password, bg="black", fg="white")
        self.generate_button.pack(pady=10)
        self.password_frame = tk.Frame(self.root, bg="black")
        self.password_frame.pack(pady=5)
        self.password_display = tk.Entry(self.password_frame, show='•')
        self.password_display.pack(side=tk.LEFT, padx=(0, 5))
        self.copy_icon_button = tk.Button(self.password_frame, text='📋', command=self.copy_to_clipboard, bg="black", fg="white")
        self.copy_icon_button.pack(side=tk.LEFT)
        self.show_password_var = tk.BooleanVar()
        self.show_password_check = ttk.Checkbutton(self.password_frame, variable=self.show_password_var, command=self.toggle_password_visibility, style="Custom.TCheckbutton")
        self.show_password_check.pack(side=tk.LEFT)
        self.strength_label = tk.Label(self.root, text="Password Strength:", bg="black", fg="white")
        self.strength_label.pack()
        self.progress = ttk.Progressbar(self.root, orient="horizontal", mode="determinate", length=200)
        self.progress.pack()
        self.save_button = tk.Button(self.root, text="Save Password to File", command=self.save_password_to_file, bg="black", fg="white")
        self.save_button.pack()
        self.history_label = tk.Label(self.root, text="Password History:", bg="black", fg="white")
        self.history_label.pack()
        self.password_listbox = tk.Listbox(self.root, bg="black", fg="white", selectbackground="gray", selectforeground="black")
        self.password_listbox.pack(padx=10, pady=5, fill="both", expand=True)
        self.password_listbox.bind("<<ListboxSelect>>", self.on_password_selected)

    def generate_password(self):
        length = int(self.password_length.get())
        charset = ""

        if self.use_lowercase.get():
            charset += string.ascii_lowercase

        if self.use_uppercase.get():
            charset += string.ascii_uppercase

        if self.use_digits.get():
            charset += string.digits

        if self.use_special_chars.get():
            charset += string.punctuation

        if not charset:
            messagebox.showerror("Error", "Please select at least one character set.")
            return

        password = ''.join(random.choice(charset) for _ in range(length))
        self.generated_password = password
        self.password_display.delete(0, tk.END)
        self.password_display.insert(0, password)
        self.show_password_strength(password)
        self.password_history.append(password)
        self.update_password_history()

    def toggle_password_visibility(self):
        if self.show_password_var.get():
            self.password_display.config(show='')
        else:
            self.password_display.config(show='•')

    def copy_to_clipboard(self):
        if hasattr(self, "generated_password"):  
            pyperclip.copy(self.generated_password)
            messagebox.showinfo("Password Copied", "Password copied to clipboard successfully.")
        else:
            messagebox.showwarning("No Password Generated", "Please generate a password first.")

    def save_password_to_file(self):
        if not self.password_history:
            messagebox.showwarning("No Passwords", "No passwords generated yet.")
            return

        file_path = filedialog.asksaveasfilename(defaultextension=".txt", filetypes=[("Text Files", "*.txt")])
        if file_path:
            with open(file_path, "w") as file:
                file.write("\n".join(self.password_history))
            messagebox.showinfo("File Saved", "Passwords saved successfully.")

    def update_password_history(self):
        self.password_listbox.delete(0, tk.END)
        for password in self.password_history:
            self.password_listbox.insert(tk.END, password)

    def on_password_selected(self, event):
        selected_index = self.password_listbox.curselection()
        if selected_index:
            selected_password = self.password_listbox.get(selected_index)
            self.copy_password_from_history(selected_password)

    def copy_password_from_history(self, password):
        pyperclip.copy(password)
        messagebox.showinfo("Password Copied", "Password copied to clipboard from history.")

    def show_password_strength(self, password):
        length_strength = min(len(password) / 20.0, 1.0)
        charset_strength = sum(
            (bool(self.use_lowercase.get()), bool(self.use_uppercase.get()), bool(self.use_digits.get()),
             bool(self.use_special_chars.get()))
        ) / 4.0
        repeated_strength = 1.0 if len(set(password)) == len(password) else 0.5

        strength_score = (length_strength + charset_strength + repeated_strength) / 3.0
        self.progress["value"] = strength_score * 100

        if strength_score < 0.33:
            strength_text = "Weak"
        elif strength_score < 0.66:
            strength_text = "Moderate"
        else:
            strength_text = "Strong"

        self.strength_label.config(text=f"Password Strength: {strength_text}")

if __name__ == "__main__":
    root = tk.Tk()
    app = PasswordGeneratorApp(root)
    root.mainloop()
