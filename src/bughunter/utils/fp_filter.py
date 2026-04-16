import re

def is_false_positive(token: str):
    # 1. თუ არის უბრალო ანბანი
    if "abcd" in token.lower() or "1234" in token:
        return True
    
    # 2. თუ არის ძალიან განმეორებადი (მაგ: aaaaaaaaaa)
    if len(set(token)) < 5:
        return True
        
    # 3. თუ არის საერთო ტექნიკური სიტყვები, რაც ტოკენს ჰგავს
    common_strings = ["version", "charset", "encoding", "content-type"]
    if any(s in token.lower() for s in common_strings):
        return True
        
    return False
