import csv, hashlib, re

class Idents:
    def __init__(self, emails, hashes, phones, names, uids):
        self.direct = [x.lower() for x in (set(emails) | set(hashes) | set(phones) | set(names)) if x]
        self.weak = [x.lower() for x in uids if x]
        self.rx_d = re.compile(
            "|".join(
                r"(?<![\w.+\-])" + re.escape(x) + r"(?![\w+\-])"
                for x in self.direct
        )
        )if self.direct else None

        self.rx_w = re.compile(
        "|".join(r"\b" + re.escape(x) + r"\b" for x in self.weak)
    ) if self.weak else None
        self.rx_w = re.compile("|".join(r"\b" + re.escape(x) + r"\b" for x in self.weak)) if self.weak else None
    def direct_in(self, t): return bool(self.rx_d and self.rx_d.search(t.lower()))
    def weak_in(self, t):   return bool(self.rx_w and self.rx_w.search(t.lower()))
    

class IdentityResolver:
    def __init__(self, ds):
        rows = list(csv.reader(open(f"{ds}/user_identities.csv", encoding="utf-8")))
        self.users = [r for r in rows if r and r[0] != "user_id"]  # id,name,email,phone,hash,created
        self.audit = list(csv.DictReader(open(f"{ds}/user_audit_log.csv", encoding="utf-8")))

    def resolve(self, email):
        e = email.strip().lower()
        uid = next((u[0] for u in self.users if u[2].lower() == e), None)
        if not uid:  # email may be an OLD address
            for a in self.audit:
                if a["field_name"] == "email" and e in (a["old_value"].lower(), a["new_value"].lower()):
                    uid = a["user_id"]; break
        emails, hashes, phones, names = {e}, set(), set(), set()
        if uid:
            for u in self.users:
                if u[0] == uid:
                    names.add(u[1]); emails.add(u[2].lower()); phones.add(u[3]); hashes.add(u[4])
            for a in self.audit:
                if a["user_id"] == uid:
                    tgt = {"email": emails, "email_hash": hashes, "phone": phones}.get(a["field_name"])
                    if tgt is not None:
                        tgt.update([a["old_value"].lower(), a["new_value"].lower()])
        hashes |= {hashlib.sha256(x.encode()).hexdigest() for x in emails}
        return Idents(emails, hashes, phones, names, [uid] if uid else [])