from coffre import Coffre


class PasswordEntry:
    def __init__(self, login, password, url, name, coffre):
        self.login = login
        self.password = password
        self.url = url
        self.name = name
        self.coffre = coffre

