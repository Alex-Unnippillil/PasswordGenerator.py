import tkinter as tk
from tkinter import messagebox, ttk, filedialog
import string
import random

try:
    import pyperclip
    PYPERCLIP_AVAILABLE = True
except ImportError:  # pragma: no cover - handled at runtime
    PYPERCLIP_AVAILABLE = False

    def _pyperclip_copy_stub(_text):
        messagebox.showwarning(
            "Pyperclip Unavailable",
            "Pyperclip is not installed. Install it to enable clipboard copying.",
        )

    class pyperclip:  # type: ignore
        copy = staticmethod(_pyperclip_copy_stub)

class Tooltip:
    def __init__(self, widget, text):
        self.widget = widget
        self.text = text
        self.tipwindow = None
        self.widget.bind("<Enter>", self.show_tip)
        self.widget.bind("<Leave>", self.hide_tip)

    def show_tip(self, _event=None):
        if self.tipwindow or not self.text:
            return
        x = self.widget.winfo_rootx() + 20
        y = self.widget.winfo_rooty() + self.widget.winfo_height() + 10
        self.tipwindow = tw = tk.Toplevel(self.widget)
        tw.wm_overrideredirect(True)
        tw.wm_geometry(f"+{x}+{y}")
        label = tk.Label(
            tw,
            text=self.text,
            background="lightyellow",
            relief="solid",
            borderwidth=1,
            font=("tahoma", "8", "normal"),
        )
        label.pack(ipadx=1)

    def hide_tip(self, _event=None):
        if self.tipwindow:
            self.tipwindow.destroy()
            self.tipwindow = None

class PasswordGeneratorApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Password Generator")
        self.root.geometry("400x440")
        self.password_length_value = tk.StringVar()
        self.password_length_value.set("7")
        self.password_history = []
        self._status_after_id = None
        self.create_widgets()
        self.create_menu()
        self.root.bind("<Control-g>", lambda e: self.generate_password())
        self.root.bind("<Control-c>", lambda e: self.copy_to_clipboard())
        self.root.bind("<Control-s>", lambda e: self.save_password_to_file())

    def create_widgets(self):
        self.root.configure(bg="black")

        self.menu_bar = tk.Menu(self.root)
        self.root.config(menu=self.menu_bar)

        file_menu = tk.Menu(self.menu_bar, tearoff=0)
        file_menu.add_command(label="Generate", command=self.generate_password)
        file_menu.add_command(label="Save", command=self.save_password_to_file)
        file_menu.add_command(label="Clear History", command=self.clear_history)
        file_menu.add_command(label="Exit", command=self.root.quit)
        self.menu_bar.add_cascade(label="File", menu=file_menu)

        edit_menu = tk.Menu(self.menu_bar, tearoff=0)
        edit_menu.add_command(label="Copy", command=self.copy_to_clipboard)
        self.menu_bar.add_cascade(label="Edit", menu=edit_menu)

        help_menu = tk.Menu(self.menu_bar, tearoff=0)
        help_menu.add_command(label="About", command=self.show_about)
        self.menu_bar.add_cascade(label="Help", menu=help_menu)
        self.title_label = tk.Label(self.root, text="PASSWORD GENERATOR", font=("Arial", 24, "bold"), bg="black", fg="white")
        self.title_label.pack(pady=10)
        self.label_length = tk.Label(self.root, text="Password Length:", bg="black", fg="white")
        self.label_length.pack()
        self.password_length = tk.Spinbox(self.root, from_=4, to=128, textvariable=self.password_length_value)
        self.password_length.pack()
        self.tooltip_length = Tooltip(self.password_length, "Set desired password length")
        self.label_charset = tk.Label(self.root, text="Character Set:", bg="black", fg="white")
        self.label_charset.pack()
        self.use_lowercase = tk.BooleanVar()
        self.use_uppercase = tk.BooleanVar()
        self.use_digits = tk.BooleanVar()
        self.use_special_chars = tk.BooleanVar()
        style = ttk.Style()
        style.configure("Custom.TCheckbutton", background="black", foreground="white")
        style.configure("Status.TLabel", background="lightgray")
        self.check_lowercase = ttk.Checkbutton(self.root, text="Lowercase", variable=self.use_lowercase, style="Custom.TCheckbutton")
        self.check_lowercase.pack()
        self.tooltip_lowercase = Tooltip(self.check_lowercase, "Include lowercase letters")
        self.check_uppercase = ttk.Checkbutton(self.root, text="Uppercase", variable=self.use_uppercase, style="Custom.TCheckbutton")
        self.check_uppercase.pack()
        self.tooltip_uppercase = Tooltip(self.check_uppercase, "Include uppercase letters")
        self.check_digits = ttk.Checkbutton(self.root, text="Digits", variable=self.use_digits, style="Custom.TCheckbutton")
        self.check_digits.pack()
        self.tooltip_digits = Tooltip(self.check_digits, "Include numbers")
        self.check_special_chars = ttk.Checkbutton(self.root, text="Special Characters", variable=self.use_special_chars, style="Custom.TCheckbutton")
        self.check_special_chars.pack()
        self.tooltip_special_chars = Tooltip(self.check_special_chars, "Include special characters")
        self.use_lowercase.set(True)
        self.use_uppercase.set(True)
        self.use_digits.set(True)
        self.use_special_chars.set(True)
        self.generate_button = tk.Button(self.root, text="Generate Password", command=self.generate_password, bg="black", fg="white")
        self.generate_button.pack(pady=10)
        self.tooltip_generate = Tooltip(self.generate_button, "Create a new password")
        self.strength_label = tk.Label(self.root, text="Password Strength:", bg="black", fg="white")
        self.strength_label.pack()
        self.progress = ttk.Progressbar(self.root, orient="horizontal", mode="determinate", length=200)
        self.progress.pack()
        self.auto_copy_var = tk.BooleanVar()
        self.auto_copy_check = ttk.Checkbutton(
            self.root,
            text="Auto-copy",
            variable=self.auto_copy_var,
            style="Custom.TCheckbutton",
        )
        self.auto_copy_check.pack()
        self.copy_button = tk.Button(self.root, text="Copy Password to Clipboard", command=self.copy_to_clipboard, bg="black", fg="white")
        self.copy_button.pack()
        self.tooltip_copy = Tooltip(self.copy_button, "Copy password to clipboard")
        self.save_button = tk.Button(self.root, text="Save Password to File", command=self.save_password_to_file, bg="black", fg="white")
        self.save_button.pack()
        self.tooltip_save = Tooltip(self.save_button, "Save passwords to file")
        self.history_label = tk.Label(self.root, text="Password History:", bg="black", fg="white")
        self.history_label.pack()
        self.password_listbox = tk.Listbox(self.root, bg="black", fg="white", selectbackground="gray", selectforeground="black")
        self.password_listbox.pack(padx=10, pady=5, fill="both", expand=True)
        self.password_listbox.bind("<<ListboxSelect>>", self.on_password_selected)
        self.status_bar = ttk.Label(self.root, text="", style="Status.TLabel", anchor="w")
        self.status_bar.pack(side="bottom", fill="x")



    def generate_password(self):
        try:
            length = int(self.password_length.get())
        except ValueError:
            messagebox.showerror("Error", "Please enter a valid number for password length.")
            return

        if not 4 <= length <= 128:
            messagebox.showerror("Error", "Password length must be between 4 and 128.")
            return
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
        if self.auto_copy_var.get():
            if PYPERCLIP_AVAILABLE:
                pyperclip.copy(password)
                self.set_status("Password generated and copied to clipboard.")
            else:
                pyperclip.copy(password)
                self.set_status("Password generated. Install pyperclip to enable copying.")
        else:
            self.set_status("Password generated.")
        self.show_password_strength(password)
        self.show_password_message(password)

    def show_password_message(self, password):
        messagebox.showinfo("Generated Password", f"Your password is:\n{password}")
        self.password_history.append(password)
        self.update_password_history()

    def set_status(self, message, timeout_ms=3000):
        self.status_bar.config(text=message)
        if self._status_after_id:
            self.root.after_cancel(self._status_after_id)
        self._status_after_id = self.root.after(timeout_ms, lambda: self.status_bar.config(text=""))

    def copy_to_clipboard(self):
        if hasattr(self, "generated_password"):
            if PYPERCLIP_AVAILABLE:
                pyperclip.copy(self.generated_password)
                self.set_status("Password copied to clipboard.")
            else:
                pyperclip.copy(self.generated_password)
                self.set_status("Install pyperclip to enable copying.")
        else:
            self.set_status("Please generate a password first.")

    def save_password_to_file(self):
        if not self.password_history:
            self.set_status("No passwords generated yet.")
            return

        file_path = filedialog.asksaveasfilename(defaultextension=".txt", filetypes=[("Text Files", "*.txt")])
        if file_path:
            with open(file_path, "w") as file:
                file.write("\n".join(self.password_history))
            self.set_status("Passwords saved successfully.")

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
        if PYPERCLIP_AVAILABLE:
            pyperclip.copy(password)
            self.set_status("Password copied to clipboard.")
        else:
            pyperclip.copy(password)
            self.set_status("Install pyperclip to enable copying.")


    def show_about(self):
        messagebox.showinfo("About", "Password Generator\nGenerate secure passwords.")

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
