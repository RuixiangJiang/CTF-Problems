URL: https://ruixiangj.top/CTF-Problems/injection/

Backend SQL table template:
```
Table: users
Columns:
  id        INTEGER PRIMARY KEY
  username  TEXT
  password  TEXT
  is_admin  INTEGER (0 or 1)
  flag      TEXT (only for admin)
```

Login SQL query template:
```
SELECT id, username, is_admin, flag
FROM users
WHERE username = '<your_username>'
  AND password = '<your_password>'
LIMIT 1;
```

Goal: login as the admin

Input Username = `admin' --` and an arbitrary password, you will get the flag.