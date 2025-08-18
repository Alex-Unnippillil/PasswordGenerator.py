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
        self.dark_mode = tk.BooleanVar(value=True)
        self.style = ttk.Style()
        self.style.configure('Dark.TCheckbutton', background='black', foreground='white')
        self.style.configure('Light.TCheckbutton', background='white', foreground='black')
        self.create_widgets()
        self.apply_theme()

    def create_widgets(self):
        self.title_label = tk.Label(self.root, text="PASSWORD GENERATOR", font=("Arial", 24, "bold"))
        self.title_label.pack(pady=10)
        self.label_length = tk.Label(self.root, text="Password Length:")
        self.label_length.pack()
        self.password_length = tk.Entry(self.root, textvariable=self.password_length_value)
        self.password_length.pack()
        self.label_charset = tk.Label(self.root, text="Character Set:")
        self.label_charset.pack()
        self.use_lowercase = tk.BooleanVar()
        self.use_uppercase = tk.BooleanVar()
        self.use_digits = tk.BooleanVar()
        self.use_special_chars = tk.BooleanVar()
        self.check_lowercase = ttk.Checkbutton(self.root, text="Lowercase", variable=self.use_lowercase)
        self.check_lowercase.pack()
        self.check_uppercase = ttk.Checkbutton(self.root, text="Uppercase", variable=self.use_uppercase)
        self.check_uppercase.pack()
        self.check_digits = ttk.Checkbutton(self.root, text="Digits", variable=self.use_digits)
        self.check_digits.pack()
        self.check_special_chars = ttk.Checkbutton(self.root, text="Special Characters", variable=self.use_special_chars)
        self.check_special_chars.pack()
        self.dark_mode_check = ttk.Checkbutton(self.root, text="Dark mode", variable=self.dark_mode, command=self.toggle_theme)
        self.dark_mode_check.pack()
        self.use_lowercase.set(True)
        self.use_uppercase.set(True)
        self.use_digits.set(True)
        self.use_special_chars.set(True)
        self.generate_button = tk.Button(self.root, text="Generate Password", command=self.generate_password)
        self.generate_button.pack(pady=10)
        self.strength_label = tk.Label(self.root, text="Password Strength:")
        self.strength_label.pack()
        self.progress = ttk.Progressbar(self.root, orient="horizontal", mode="determinate", length=200)
        self.progress.pack()
        self.copy_button = tk.Button(self.root, text="Copy Password to Clipboard", command=self.copy_to_clipboard)
        self.copy_button.pack()
        self.save_button = tk.Button(self.root, text="Save Password to File", command=self.save_password_to_file)
        self.save_button.pack()
        self.history_label = tk.Label(self.root, text="Password History:")
        self.history_label.pack()
        self.password_listbox = tk.Listbox(self.root)
        self.password_listbox.pack(padx=10, pady=5, fill="both", expand=True)
        self.password_listbox.bind("<<ListboxSelect>>", self.on_password_selected)
        self.checkbuttons = [
            self.check_lowercase,
            self.check_uppercase,
            self.check_digits,
            self.check_special_chars,
            self.dark_mode_check,
        ]

    def toggle_theme(self):
        self.apply_theme()

    def apply_theme(self):
        if self.dark_mode.get():
            bg_color = "black"
            fg_color = "white"
            style_name = 'Dark.TCheckbutton'
            self.style.theme_use('clam')
        else:
            bg_color = "white"
            fg_color = "black"
            style_name = 'Light.TCheckbutton'
            self.style.theme_use('default')

        self.style.configure('TProgressbar', background=fg_color)
        for cb in self.checkbuttons:
            cb.configure(style=style_name)

        self.root.configure(bg=bg_color)
        labels = [self.title_label, self.label_length, self.label_charset,
                  self.strength_label, self.history_label]
        for label in labels:
            label.configure(bg=bg_color, fg=fg_color)

        buttons = [self.generate_button, self.copy_button, self.save_button]
        for btn in buttons:
            btn.configure(bg=bg_color, fg=fg_color)

        self.password_length.configure(bg=bg_color, fg=fg_color, insertbackground=fg_color)
        self.password_listbox.configure(
            bg=bg_color,
            fg=fg_color,
            selectbackground="gray" if self.dark_mode.get() else "lightgray",
            selectforeground=bg_color,
        )

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
        self.show_password_strength(password)
        self.show_password_message(password)

    def show_password_message(self, password):
        messagebox.showinfo("Generated Password", f"Your password is:\n{password}")
        self.password_history.append(password)
        self.update_password_history()

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
