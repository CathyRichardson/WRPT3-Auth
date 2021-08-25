INSERT INTO users1(username, password, email, first_name, admin)
VALUES($1, $2, $3, $4, $5)
returning id, username, email, admin;