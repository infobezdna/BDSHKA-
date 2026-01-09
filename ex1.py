import re
import json
import base64
import os

# КОНФИГУРАЦИЯ
RISK_THRESHOLD = 5
SECRET_KEY = "coursework_secret_key"

SUSPICIOUS_PATTERNS = {
    r"or\s+1\s*=\s*1": 5,
    r"\sunion\s": 6,
    r"\bdrop\b": 10,
    r"\balter\b": 6,
    r"--": 2
}


def encrypt(text: str) -> str:
    key = SECRET_KEY.encode()
    data = text.encode()
    encrypted_bytes = bytearray()
    for i in range(len(data)):
        encrypted_bytes.append(data[i] ^ key[i % len(key)])
    return base64.b64encode(encrypted_bytes).decode()


def analyze_query(sql_query: str):
    risk_score = 0
    found_patterns = []
    query_lower = sql_query.lower()

    for pattern, score in SUSPICIOUS_PATTERNS.items():
        if re.search(pattern, query_lower):
            risk_score += score
            found_patterns.append(pattern)

    return risk_score, found_patterns


def main():
    if not os.path.exists("alerts"):
        os.makedirs("alerts")

    alert_count = 0


    print("Начинаю анализ логов...")

    try:
        with open("rdb_logs.txt", "r", encoding="utf-8") as file:
            for line in file:
                if "query=" not in line:
                    continue

                parts = line.split("|")
                if len(parts) < 3:
                    continue

                timestamp = parts[0].strip()
                user = parts[1].split("=")[1].strip()
                query = parts[2].split("query=")[1].strip()

                risk, patterns = analyze_query(query)

                if risk >= RISK_THRESHOLD:
                    alert_count += 1
                    report = {
                        "id": alert_count,
                        "timestamp": timestamp,
                        "user": user,
                        "query": query,
                        "risk": risk,
                        "patterns": patterns
                    }

                    json_str = json.dumps(report, ensure_ascii=False, indent=2)
                    encrypted_data = encrypt(json_str)

                    filename = f"alerts/alert_{alert_count:03}.enc"
                    with open(filename, "w", encoding="utf-8") as f:
                        f.write(encrypted_data)


                    print(f"[!] Обнаружена угроза! Сохранен отчет: {filename}")

    except FileNotFoundError:

        print("Ошибка: Файл rdb_logs.txt не найден! Проверь папку с программой.")


if __name__ == "__main__":
    main()