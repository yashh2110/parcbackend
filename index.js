const express = require("express");
const mysql = require("mysql2");
const bodyParser = require("body-parser");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const { check, validationResult } = require("express-validator");
const app = express();
const port = 3000;
const saltRounds = 10;
const jwtSecret = "secretkey";

// const db = mysql.createConnection({
//   host: "127.0.0.1",
//   user: "root",
//   password: "yash",
//   database: "parc",
// });

// db.connect((err) => {
//   if (err) {
//     console.log("Failed to connect to MySQL database");
//     throw err;
//   }
//   console.log("Connected to MySQL database");
// });

app.use(bodyParser.json());

app.post(
  "/register",
  [check("email").isEmail(), check("password").isLength({ min: 6 })],
  (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(422).json({ errors: errors.array() });
    }

    const { email, password, name } = req.body;

    bcrypt.hash(password, saltRounds, (err, hash) => {
      if (err) {
        throw err;
      }

      const user = { user_email: email, user_password: hash, user_name: name };
      const sql = "INSERT INTO users SET ?";

      db.query(sql, user, (err) => {
        if (err) {
          return res.status(500).json({ message: "Could not register user." });
        }
        res.status(201).json({ message: "User registered successfully." });
      });
    });
  }
);

app.post(
  "/login",
  [
    check("email").isEmail().normalizeEmail(),
    check("password").isLength({ min: 6 }),
  ],
  (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(422).json({ errors: errors.array() });
    }

    const { email, password } = req.body;
    const sql = "SELECT * FROM users WHERE ?";

    db.query(sql, { user_email: email }, (err, results) => {
      if (err) {
        throw err;
      }
      console.log(results);

      if (results.length === 0) {
        return res.status(401).json({ message: "Authentication failed." });
      }
      const user = results[0];

      bcrypt.compare(password, user.user_password, (err, result) => {
        if (err) {
          throw err;
        }

        if (!result) {
          return res.status(401).json({ message: "Authentication failed." });
        }

        const token = jwt.sign({ email: user.user_email }, jwtSecret, {
          expiresIn: "1h",
        });
        res.status(200).json({ message: "Authentication successful.", token });
      });
    });
  }
);

function verifyToken(req, res, next) {
  const authHeader = req.headers.authorization;
  if (!authHeader) {
    return res.status(401).json({ message: "Authorization header not found." });
  }

  const token = authHeader.split(" ")[1];
  jwt.verify(token, jwtSecret, (err, decoded) => {
    if (err) {
      return res.status(401).json({ message: "Invalid token." });
    }
    req.user = decoded;
    next();
  });
}

app.get("/user", verifyToken, (req, res) => {
  const email = req.user.email;
  const sql = "SELECT user_email FROM users WHERE user_email = ?";

  db.query(sql, { user_email: email }, (err, results) => {
    if (err) {
      console.log(err);
      return res.status(500).json({ message: "Internal Server Error" });
    }
    if (!results || results.length === 0) {
      return res.status(404).json({ message: "User not found" });
    }
    const user = {
      email: results[0].user_email,
      name: results[0].user_name,
    };
    res.status(200).json({ user });
  });
});

app.post("/hardware/sensor-data", (req, res) => {
  console.log(req.body);
  return res
    .status(200)
    .json({ data: req.body, msg: "data transfer successull" });
});

app.listen(process.env.PORT || port, () => {
  console.log(`Server listening on port ${port}`);
});
