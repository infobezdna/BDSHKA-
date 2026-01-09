import tkinter as tk
from tkinter import messagebox
import os
import json
import base64

SECRET_KEY = "coursework_secret_key"


def decrypt(encrypted_str: str) -> str:
    """Функция обратная шифрованию (XOR работает в обе стороны одинаково)."""
    try:
        key = SECRET_KEY.encode()
        encrypted_bytes = base64.b64decode(encrypted_str)

        decrypted_bytes = bytearray()
        for i in range(len(encrypted_bytes)):
            decrypted_bytes.append(encrypted_bytes[i] ^ key[i % len(key)])

        return decrypted_bytes.decode()
    except Exception as e:
        return "Ошибка дешифровки"


def load_alerts():
    """Загружает список файлов из папки alerts в список на экране."""
    listbox.delete(0, tk.END)  # Очистить список
    if not os.path.exists("alerts"):
        os.makedirs("alerts")

    files = sorted([f for f in os.listdir("alerts") if f.endswith(".enc")])
    for file in files:
        listbox.insert(tk.END, file)


def show_report(event):
    """Показывает расшифрованный отчет при клике на файл."""
    selection = listbox.curselection()
    if not selection:
        return

    filename = listbox.get(selection[0])
    path = os.path.join("alerts", filename)

    with open(path, "r", encoding="utf-8") as f:
        encrypted_content = f.read()

    # Дешифровка
    json_text = decrypt(encrypted_content)

    # Красивый вывод в текстовое поле
    try:
        data = json.loads(json_text)
        result = (f"ВРЕМЯ: {data['timestamp']}\n"
                  f"ПОЛЬЗОВАТЕЛЬ: {data['user']}\n"
                  f"УРОВЕНЬ РИСКА: {data['risk']}\n"
                  f"ПАТТЕРНЫ АТАКИ: {data['patterns']}\n"
                  f"{'-' * 40}\n"
                  f"SQL ЗАПРОС:\n{data['query']}")
    except:
        result = "Не удалось прочитать JSON. Возможно, неверный ключ."

    text_area.delete(1.0, tk.END)  # Очистить поле
    text_area.insert(tk.END, result)


# Создание окна
root = tk.Tk()
root.title("Мониторинг безопасности РЕД БД by Denis Burlakov")
root.geometry("600x400")

# Левая панель (Список файлов)
frame_list = tk.Frame(root)
frame_list.pack(side=tk.LEFT, fill=tk.Y, padx=10, pady=10)

tk.Label(frame_list, text="Список инцидентов:").pack()
listbox = tk.Listbox(frame_list, width=25, height=20)
listbox.pack(fill=tk.Y, expand=True)
listbox.bind('<<ListboxSelect>>', show_report)  # При клике вызывать show_report

# Правая панель (Текст отчета)
frame_detail = tk.Frame(root)
frame_detail.pack(side=tk.RIGHT, fill=tk.BOTH, expand=True, padx=10, pady=10)

tk.Label(frame_detail, text="Детали инцидента:").pack()
text_area = tk.Text(frame_detail, height=20, width=40)
text_area.pack(fill=tk.BOTH, expand=True)

# Кнопка обновить
btn = tk.Button(frame_list, text="Обновить список", command=load_alerts)
btn.pack(pady=5)

# Запуск
load_alerts()
root.mainloop()