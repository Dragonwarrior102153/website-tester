class Cookie():
    def __init__(self, Name, Secure, HttpOnly, SameSite, Domain, Path, Expires, MaxAge, Partitioned, Priority) -> None:
        self.cookieAttr = {
        "Name": Name,
        "Secure": Secure,
        "HttpOnly": HttpOnly,
        "SameSite": SameSite,
        "Domain": Domain,
        "Path": Path,
        "Expires": Expires,
        "MaxAge": MaxAge,
        "Partitioned": Partitioned,
        "Priority": Priority
        }

    def __repr__(self):
        return str(self.cookieAttr)