import tkinter as tk
from tkinter import ttk, messagebox
import random
import string
import hashlib
import pyqrcode
from io import BytesIO
import threading

# --- Fichier pour enregistrer les mots de passe ---
passwords_file = "passwords.csv"

# --- Initialisation de la fenêtre ---
root = tk.Tk()
root.title("Gestion et Générateur de Mots de Passe")
root.geometry("1000x850")
root.configure(bg="#f1c6d8")  # Couleur de fond rose

# --- Multilingue ---
languages = {
    "en": {
        "title": "Password Manager & Generator",
        "generate": "Generate a Password",
        "verify": "Verify Password Strength",
        "qr_code": "Generate QR Code",
        "password_copied": "Password copied to clipboard!",
        "clipboard_cleared": "Clipboard cleared!",
        "generate_qr": "Generate QR Code",
        "copy_password": "Copy Password",
        "language": "Language",
        "hash_password": "Hash the Password",
    },
    "fr": {
        "title": "Gestion et Générateur de Mots de Passe",
        "generate": "Générer un Mot de Passe",
        "verify": "Vérifier la Force d'un Mot de Passe",
        "qr_code": "Générer un QR Code",
        "password_copied": "Mot de passe copié dans le presse-papiers !",
        "clipboard_cleared": "Presse-papiers vidé !",
        "generate_qr": "Générer un QR Code",
        "copy_password": "Copier le Mot de Passe",
        "language": "Langue",
        "hash_password": "Hacher le Mot de Passe",
    }
}

current_language = "en"


def translate(key):
    """Récupère la traduction pour une clé donnée."""
    return languages[current_language].get(key, key)


# --- Styles ---
styles = {
    "bg": "#f1c6d8",  # Rose clair
    "fg": "#2d2d2d",  # Texte sombre
    "btn_bg": "#d35b87",  # Rose pour les boutons
    "btn_fg": "#ffffff",
    "progress_danger": "#ff2e63",
    "progress_warning": "#ffc107",
    "progress_success": "#6ef57a",
    "highlight": "#f7d4e0",  # Rose clair pour les zones mises en surbrillance
}

title_font = ("Helvetica", 18, "bold")
label_font = ("Helvetica", 12)
button_font = ("Helvetica", 12, "bold")

# --- Barre de progression stylisée ---
style = ttk.Style(root)
style.theme_use("clam")
style.configure("danger.Horizontal.TProgressbar", troughcolor=styles["bg"], background=styles["progress_danger"])
style.configure("warning.Horizontal.TProgressbar", troughcolor=styles["bg"], background=styles["progress_warning"])
style.configure("success.Horizontal.TProgressbar", troughcolor=styles["bg"], background=styles["progress_success"])

# --- Copier et vider le presse-papiers ---
def copier_dans_presse_papiers(password):
    """Copie un mot de passe dans le presse-papiers et le vide après 10 secondes."""
    root.clipboard_clear()
    root.clipboard_append(password)
    root.update()
    messagebox.showinfo(translate("password_copied"))

    def effacer_presse_papiers():
        threading.Timer(10, lambda: root.clipboard_clear()).start()
        messagebox.showinfo(translate("clipboard_cleared"))

    effacer_presse_papiers()


# --- Génération de mots de passe robuste (basé sur des mots) ---
def generer_mot_de_passe(longueur=12):
    """Génère un mot de passe robuste basé sur des mots, séparateurs et chiffres."""
    if longueur < 8:
        messagebox.showerror("Erreur", "La longueur minimale est de 8 caractères.")
        return None

    mots_courants = ["arbre", "nuage", "soleil", "lune", "fleur", "chat", "chien", "pomme", "éclair", 
                     "rivière", "vent", "pluie", "feuille", "étoile"]

    # Choisir deux mots aléatoires
    mots = random.sample(mots_courants, 2)
    separateur = random.choice("@#$%^&+=")  # Séparateur aléatoire
    chiffre = random.choice(string.digits)  # Un chiffre aléatoire

    # Capitaliser le premier mot
    mots[0] = mots[0].capitalize()
    mot_de_passe = separateur.join(mots) + chiffre

    # Compléter avec des caractères supplémentaires si nécessaire
    caracteres_supplementaires = string.ascii_letters + string.digits + "@#$%^&+="
    while len(mot_de_passe) < longueur:
        mot_de_passe += random.choice(caracteres_supplementaires)

    return mot_de_passe


# --- Hachage du mot de passe ---
def hacher_mot_de_passe(password):
    """Hache le mot de passe en utilisant SHA256."""
    sha256 = hashlib.sha256()
    sha256.update(password.encode('utf-8'))
    return sha256.hexdigest()


# --- Vérification de la force du mot de passe ---
def verifier_force_mot_de_passe(password):
    """Vérifie la force d'un mot de passe."""
    score = 0
    if len(password) >= 8:
        score += 1
    if any(c.islower() for c in password):
        score += 1
    if any(c.isupper() for c in password):
        score += 1
    if any(c.isdigit() for c in password):
        score += 1
    if any(c in "@#$%^&*!" for c in password):
        score += 1
    return score


def mettre_a_jour_progression(password):
    """Met à jour la barre de progression et sa couleur en fonction de la force."""
    score = verifier_force_mot_de_passe(password)
    progress_bar["value"] = score

    if score <= 2:
        progress_bar.configure(style="danger.Horizontal.TProgressbar")
    elif score <= 4:
        progress_bar.configure(style="warning.Horizontal.TProgressbar")
    else:
        progress_bar.configure(style="success.Horizontal.TProgressbar")


# --- Générer un QR Code ---
def generer_qr_code(password):
    """Génère un QR code pour le mot de passe."""
    qr = pyqrcode.create(password)
    buffer = BytesIO()
    qr.png(buffer, scale=8)

    top = tk.Toplevel(root)
    top.title("QR Code")
    top.geometry("300x300")
    top.configure(bg=styles["bg"])

    img = tk.PhotoImage(data=buffer.getvalue())
    label = tk.Label(top, image=img, bg=styles["bg"])
    label.image = img
    label.pack(pady=10)


# --- Changer la langue ---
def changer_langue(langue):
    global current_language
    current_language = langue
    mettre_a_jour_interface()


def mettre_a_jour_interface():
    label_title.config(text=translate("title"))
    button_generate.config(text=translate("generate"))
    label_verify.config(text=translate("verify"))
    button_copy.config(text=translate("copy_password"))
    button_qr.config(text=translate("generate_qr"))
    checkbox_hash.config(text=translate("hash_password"))


# --- Interface principale ---
# Titre
label_title = tk.Label(root, text=translate("title"), font=title_font, bg=styles["bg"], fg=styles["fg"])
label_title.pack(pady=20)

# Sélecteur de langue
frame_language = tk.Frame(root, bg=styles["highlight"])
frame_language.pack(pady=10, fill="x", padx=20)

label_language = tk.Label(frame_language, text=translate("language"), font=label_font, bg=styles["highlight"], fg=styles["fg"])
label_language.pack(side="left", padx=10)

combo_language = ttk.Combobox(frame_language, values=list(languages.keys()), state="readonly", width=10)
combo_language.set("en")
combo_language.pack(side="left")
combo_language.bind("<<ComboboxSelected>>", lambda e: changer_langue(combo_language.get()))

# Génération de mot de passe
frame_generation = tk.Frame(root, bg=styles["highlight"], padx=20, pady=20)
frame_generation.pack(pady=20, fill="x", padx=30)

entry_length = tk.Entry(frame_generation, font=label_font, width=10)
entry_length.insert(0, "12")
entry_length.pack(pady=5)


def afficher_mot_de_passe():
    longueur = int(entry_length.get())
    password = generer_mot_de_passe(longueur)
    if password:
        label_result_generation.config(text=f"Mot de passe généré : {password}")
        if var_hash.get():
            hashed_password = hacher_mot_de_passe(password)
            messagebox.showinfo("Hachage", f"Mot de passe haché : {hashed_password}")
            generer_qr_code(hashed_password)
        else:
            label_result_generation.config(text=f"Mot de passe généré : {password}")


button_generate = tk.Button(frame_generation, text=translate("generate"), font=button_font, bg=styles["btn_bg"], fg=styles["btn_fg"], command=afficher_mot_de_passe)
button_generate.pack(pady=5)

label_result_generation = tk.Label(frame_generation, text="", font=label_font, bg=styles["highlight"], fg=styles["fg"])
label_result_generation.pack(pady=5)

button_copy = tk.Button(frame_generation, text=translate("copy_password"), font=button_font, bg=styles["btn_bg"], fg=styles["btn_fg"], command=lambda: copier_dans_presse_papiers(label_result_generation.cget("text")))
button_copy.pack(pady=5)

# Section vérification
frame_verification = tk.Frame(root, bg=styles["highlight"], padx=20, pady=20)
frame_verification.pack(pady=20, fill="x", padx=30)

label_verify = tk.Label(frame_verification, text=translate("verify"), font=label_font, bg=styles["highlight"], fg=styles["fg"])
label_verify.pack(anchor="w")

entry_password = tk.Entry(frame_verification, font=label_font, width=40)
entry_password.pack(pady=5)

progress_bar = ttk.Progressbar(frame_verification, orient="horizontal", length=400, mode="determinate", maximum=5)
progress_bar.pack(pady=10)

def verifier_et_afficher_force():
    password = entry_password.get()
    mettre_a_jour_progression(password)


button_verify = tk.Button(frame_verification, text=translate("verify"), font=button_font, bg=styles["btn_bg"], fg=styles["btn_fg"], command=verifier_et_afficher_force)
button_verify.pack(pady=5)

button_qr = tk.Button(frame_verification, text=translate("generate_qr"), font=button_font, bg=styles["btn_bg"], fg=styles["btn_fg"], command=lambda: generer_qr_code(entry_password.get()))
button_qr.pack(pady=5)

# Ajouter la case à cocher pour le hachage
var_hash = tk.BooleanVar()
checkbox_hash = tk.Checkbutton(frame_generation, text=translate("hash_password"), variable=var_hash, bg=styles["highlight"], fg=styles["fg"])
checkbox_hash.pack(pady=5)

# --- Lancement de la fenêtre ---
root.mainloop()
