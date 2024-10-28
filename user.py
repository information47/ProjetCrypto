class User:
    def __init__(self, email, password):
        self.email = email
        self.password = password
        self.coffres = []

    def add_coffre(self, coffre):
        self.coffres.append(coffre)
