import tkinter as tk
from tkinter import messagebox, ttk, filedialog
import string
import random
import pyperclip
import json
import os

class PasswordGeneratorApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Password Generator")
        self.settings_file = "settings.json"
        self.settings = self.load_settings()

        # Window geometry and variables
        self.root.geometry(self.settings.get("geometry", "400x440"))

        self.password_length_value = tk.StringVar()
        self.password_length_value.set(str(self.settings.get("password_length", 7)))
        self.password_length_value.trace_add("write", self.on_pref_change)

        self.use_lowercase = tk.BooleanVar(value=self.settings.get("use_lowercase", True))
        self.use_lowercase.trace_add("write", self.on_pref_change)
        self.use_uppercase = tk.BooleanVar(value=self.settings.get("use_uppercase", True))
        self.use_uppercase.trace_add("write", self.on_pref_change)
        self.use_digits = tk.BooleanVar(value=self.settings.get("use_digits", True))
        self.use_digits.trace_add("write", self.on_pref_change)
        self.use_special_chars = tk.BooleanVar(value=self.settings.get("use_special_chars", True))
        self.use_special_chars.trace_add("write", self.on_pref_change)

        self.theme = tk.StringVar(value=self.settings.get("theme", "dark"))
        self.theme.trace_add("write", self.on_theme_change)

        self.password_history = []
        self.set_theme_colors()
        self.create_widgets()
        self.apply_theme()
        self.root.protocol("WM_DELETE_WINDOW", self.on_exit)

    def create_widgets(self):
        self.root.configure(bg=self.bg_color)
        self.title_label = tk.Label(self.root, text="PASSWORD GENERATOR", font=("Arial", 24, "bold"), bg=self.bg_color, fg=self.fg_color)
        self.title_label.pack(pady=10)
        self.label_length = tk.Label(self.root, text="Password Length:", bg=self.bg_color, fg=self.fg_color)
        self.label_length.pack()
        self.password_length = tk.Entry(self.root, textvariable=self.password_length_value)
        self.password_length.pack()
        self.label_charset = tk.Label(self.root, text="Character Set:", bg=self.bg_color, fg=self.fg_color)
        self.label_charset.pack()
        style = ttk.Style()
        style.configure("Custom.TCheckbutton", background=self.bg_color, foreground=self.fg_color)
        self.check_lowercase = ttk.Checkbutton(self.root, text="Lowercase", variable=self.use_lowercase, style="Custom.TCheckbutton")
        self.check_lowercase.pack()
        self.check_uppercase = ttk.Checkbutton(self.root, text="Uppercase", variable=self.use_uppercase, style="Custom.TCheckbutton")
        self.check_uppercase.pack()
        self.check_digits = ttk.Checkbutton(self.root, text="Digits", variable=self.use_digits, style="Custom.TCheckbutton")
        self.check_digits.pack()
        self.check_special_chars = ttk.Checkbutton(self.root, text="Special Characters", variable=self.use_special_chars, style="Custom.TCheckbutton")
        self.check_special_chars.pack()
        self.label_theme = tk.Label(self.root, text="Theme:", bg=self.bg_color, fg=self.fg_color)
        self.label_theme.pack()
        self.theme_option = ttk.OptionMenu(self.root, self.theme, self.theme.get(), "dark", "light")
        self.theme_option.pack()
        self.generate_button = tk.Button(self.root, text="Generate Password", command=self.generate_password, bg=self.bg_color, fg=self.fg_color)
        self.generate_button.pack(pady=10)
        self.strength_label = tk.Label(self.root, text="Password Strength:", bg=self.bg_color, fg=self.fg_color)
        self.strength_label.pack()
        self.progress = ttk.Progressbar(self.root, orient="horizontal", mode="determinate", length=200)
        self.progress.pack()
        self.copy_button = tk.Button(self.root, text="Copy Password to Clipboard", command=self.copy_to_clipboard, bg=self.bg_color, fg=self.fg_color)
        self.copy_button.pack()
        self.save_button = tk.Button(self.root, text="Save Password to File", command=self.save_password_to_file, bg=self.bg_color, fg=self.fg_color)
        self.save_button.pack()
        self.history_label = tk.Label(self.root, text="Password History:", bg=self.bg_color, fg=self.fg_color)
        self.history_label.pack()
        self.password_listbox = tk.Listbox(self.root, bg=self.bg_color, fg=self.fg_color, selectbackground=self.select_bg, selectforeground=self.select_fg)
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

    def set_theme_colors(self):
        if self.theme.get() == "light":
            self.bg_color = "white"
            self.fg_color = "black"
            self.select_bg = "lightgray"
            self.select_fg = "black"
        else:
            self.bg_color = "black"
            self.fg_color = "white"
            self.select_bg = "gray"
            self.select_fg = "black"

    def apply_theme(self):
        self.set_theme_colors()
        widgets = [
            self.title_label,
            self.label_length,
            self.label_charset,
            self.label_theme,
            self.strength_label,
            self.history_label,
        ]
        for widget in widgets:
            widget.configure(bg=self.bg_color, fg=self.fg_color)
        self.root.configure(bg=self.bg_color)
        self.password_listbox.configure(bg=self.bg_color, fg=self.fg_color, selectbackground=self.select_bg, selectforeground=self.select_fg)
        self.generate_button.configure(bg=self.bg_color, fg=self.fg_color)
        self.copy_button.configure(bg=self.bg_color, fg=self.fg_color)
        self.save_button.configure(bg=self.bg_color, fg=self.fg_color)
        style = ttk.Style()
        style.configure("Custom.TCheckbutton", background=self.bg_color, foreground=self.fg_color)

    def load_settings(self):
        if os.path.exists(self.settings_file):
            try:
                with open(self.settings_file, "r") as file:
                    return json.load(file)
            except json.JSONDecodeError:
                return {}
        return {}

    def save_settings(self, *args):
        settings = {
            "password_length": self.password_length_value.get(),
            "use_lowercase": self.use_lowercase.get(),
            "use_uppercase": self.use_uppercase.get(),
            "use_digits": self.use_digits.get(),
            "use_special_chars": self.use_special_chars.get(),
            "theme": self.theme.get(),
            "geometry": self.root.winfo_geometry(),
        }
        with open(self.settings_file, "w") as file:
            json.dump(settings, file)

    def on_pref_change(self, *args):
        self.save_settings()

    def on_theme_change(self, *args):
        self.apply_theme()
        self.save_settings()

    def on_exit(self):
        self.save_settings()
        self.root.destroy()

if __name__ == "__main__":
    root = tk.Tk()
    app = PasswordGeneratorApp(root)
    root.mainloop()
