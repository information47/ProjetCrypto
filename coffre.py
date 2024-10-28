from user import User


class Coffre:
    def __init__(self, nom_coffre, password_coffre, user):
        self.nom_coffre = nom_coffre
        self.password_coffre = password_coffre
        self.user = user
        self.password_entries = []

    def add_password_entry(self, password_entry):
        self.password_entries.append(password_entry)
