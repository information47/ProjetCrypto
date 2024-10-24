CREATE TABLE User (
    Id_user INT AUTO_INCREMENT PRIMARY KEY,
    email VARCHAR(255) NOT NULL UNIQUE,
    password VARCHAR(128) NOT NULL
);

CREATE TABLE Coffre (
    Id_coffre INT AUTO_INCREMENT PRIMARY KEY,
    nom_coffre VARCHAR(255) NOT NULL,
    password_coffre VARCHAR(128),
    id_user INT,
    FOREIGN KEY (id_user) REFERENCES User(Id_user) ON DELETE CASCADE
);

CREATE TABLE PasswordEntry (
    Id_PasswordEntry INT AUTO_INCREMENT PRIMARY KEY,
    login VARCHAR(255),
    password VARCHAR(128),
    url VARCHAR(255),
    name VARCHAR(255),
    id_coffre INT,
    FOREIGN KEY (id_coffre) REFERENCES Coffre(Id_coffre) ON DELETE CASCADE
);
