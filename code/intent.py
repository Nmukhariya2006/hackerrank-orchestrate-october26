import re
NEG = [
    r"\b(not|n't)\s+(a\s+request\s+to\s+|asking\s+(for|to)\s+)?(delet|erase|remov|clos)",
    r"\bdo\s+not\s+(close|delete|erase|remove)",
    r"\bdon'?t\s+(close|delete|erase|remove)",
    r"\bleave\b.{0,40}\b(active|in place|as it is)",
    r"\bkeep\b.{0,30}\b(account|as it is)",
    r"\bwithout removing", r"\bmarketing lists only",
    r"\bcontinue using", r"\bstill (need|use)\b",
    r"\b(download|copy of|reset the login|change the email|replace it|correct it|stop the promotional)",
]
DEL = r"delet|erase|remov|clos|eliminaci|exclus|supprim|suppress|削除|삭제"


def is_deletion(text):
    text = (text or "").lower()

    keywords = (
        "delete", "deletion", "remove", "removal",
        "erase", "erasure", "forget me",
        "right to be forgotten",
        "close my account", "close the account",
        "close this account", "account closure",
        "personal data", "personal details",
        "personal information", "privacy request",
        "delete my account", "remove my account",
        "erase my data", "close my profile",
        "remove the profile", "delete my profile"
    )

    return any(word in text for word in keywords)
