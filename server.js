const passport = require('passport');
const passportJWT = require('passport-jwt');
const jwt = require('jsonwebtoken');
const express = require('express');
const app = express();

const ExtractJwt = passportJWT.ExtractJwt;
const JwtStrategy = passportJWT.Strategy;

const cors = require("cors");
const dotenv = require("dotenv");
dotenv.config();
const userService = require("./user-service.js");

const HTTP_PORT = process.env.PORT || 8080;

const strategy = new JwtStrategy(jwtOptions, (jwt_payload, next) => {
    // jwt_payload should contain: { _id, userName }
    if (jwt_payload) {
        next(null, jwt_payload);
    } else {
        next(null, false);
    }
});

passport.use(strategy);
app.use(passport.initialize());

app.use(express.json());
app.use(cors());

app.post("/api/user/register", (req, res) => {
    userService.registerUser(req.body)
        .then((msg) => {
            res.json({ "message": msg });
        }).catch((msg) => {
            res.status(422).json({ "message": msg });
        });
});

app.post("/api/user/login", (req, res) => {
    userService.checkUser(req.body)
        .then((user) => {
            // 1. Build payload
            const payload = {
                _id: user._id,
                userName: user.userName
            };

            // 2. Sign the token
            const token = jwt.sign(payload, process.env.JWT_SECRET);

            // 3. Return token in response
            res.json({ message: "login successful", token });
        })
        .catch((err) => {
            res.status(422).json({ message: err });
        });
});

app.get("/api/user/favourites", (req, res) => {
    passport.authenticate('jwt', { session: false }), (req, res) => {
        userService.getFavourites(req.user._id)
            .then(data => res.json(data))
            .catch(err => res.status(500).json({ message: err }));

    }
});

app.put("/api/user/favourites/:id",
  passport.authenticate('jwt', { session: false }),
  (req, res) => {
    userService.addFavourite(req.user._id, req.params.id)
      .then(data => res.json(data))
      .catch(err => res.status(500).json({ message: err }));
  }
);

app.delete("/api/user/favourites/:id",
  passport.authenticate('jwt', { session: false }),
  (req, res) => {
    userService.removeFavourite(req.user._id, req.params.id)
      .then(data => res.json(data))
      .catch(err => res.status(500).json({ message: err }));
  }
);

userService.connect()
    .then(() => {
        app.listen(HTTP_PORT, () => { console.log("API listening on: " + HTTP_PORT) });
    })
    .catch((err) => {
        console.log("unable to start the server: " + err);
        process.exit();
    });