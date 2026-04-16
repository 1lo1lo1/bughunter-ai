import math

def calculate_entropy(data: str) -> float:
    if not data or len(data) < 8:
        return 0
    entropy = 0
    for x in range(256):
        p_x = float(data.count(chr(x))) / len(data)
        if p_x > 0:
            entropy += - p_x * math.log(p_x, 2)
    return entropy

def is_suspicious_token(data: str, threshold: float = 3.9) -> bool:
    # მაღალი ენტროპია + სიმბოლოების ნაზავი = სავარაუდო გასაღები
    has_digit = any(c.isdigit() for c in data)
    has_upper = any(c.isupper() for c in data)
    if has_digit and has_upper and calculate_entropy(data) > threshold:
        return True
    return False
