const express = require("express");
const bodyParser = require("body-parser");
const jwt = require("jsonwebtoken");
const bcrypt = require("bcrypt");
const cors = require("cors");

const { prisma } = require("./generated/prisma-client");

const app = express();

app.secert = "monkaS";

app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: false }));
app.use(cors());

// json web token middleware
async function loginRequired(req, res, next) {
    const bearerHeader = req.headers.authorization;
    if (typeof bearerHeader !== "undefined") {
        const bearer = bearerHeader.split(" ");
        const token = bearer[1];
        jwt.verify(token, app.secert, async (err, authData) => {
            if (err) {
                res.status(401).json({
                    statusText: "You're not authed"
                });
            } else {
                // Handle if someone uses an old token that no longer exists
                let user = await prisma.user({ id: authData.id });
                if (!user) {
                    res.status(401).json({
                        statusText: "Invalid auth data"
                    });
                }
                req.token = authData;
                req.user = user;
                next();
            }
        });
    } else { // if no auth header was sent
        res.status(401).json({
            statusText: "No auth header"
        });
    }
}
// Check if admin
function adminRequired(req, res, next) {
    if (req.user.role === "ADMIN") {
        next();
    } else {
        res.status(403).json({
            statusText: "You're not an admin",
        });
    }
}

app.get("/api/v1/auth/signup", async (req, res) => {
    const {
        username,
        password,
        email
    } = req.body;

    if (username, password, email) {
        // TODO: Find a better way to do this
        let usernameTaken = await prisma.user({ username });
        let emailTaken = await prisma.user({ email });
        if (usernameTaken || emailTaken) {
            if (usernameTaken) {
                res.status(409).json({
                    statusText: "Username taken"
                });
            } else {
                res.status(409).json({
                    statusText: "Email taken"
                });
            }
        } else {
            let user = await prisma.createUser({
                username,
                password: bcrypt.hashSync(password, 12),
                email
            });
            res.status(201).json({
                statusText: "User created",
                user
            });
        }
    } else {
        res.status(400).json({
            statusText: "Invalid form data"
        });
    }
});

app.post("/api/v1/auth", async (req, res) => {
    const { username, password } = req.body;
    if (username && password) {
        const user = await prisma.user({ username });
        if (user) {
            if (bcrypt.compareSync(password, user.password)) {
                const token = jwt.sign({ id: user.id }, app.secert);
                res.json({
                    statusText: "You've been logged in!",
                    token: token
                });
            } else {
                res.status(401).json({
                    statusText: "Invalid username or password"
                });
            }
        } else {
            res.status(401).json({
                statusText: "Invalid username or password"
            });
        }
    } else {
        res.status(400).json({
            statusText: "Invalid form data"
        });
    }
});

app.get("/api/v1/paste/:id", async (req, res) => {
    const paste = await prisma.paste({ id: req.params.id ? req.params.id : "" });
    if (paste) {
        res.status(201).json({
            statusText: "success",
            paste
        });
    } else {
        res.status(404).json({
            statusText: `No paste by that ID ${req.params.id}`
        });
    }
});

app.delete("/api/v1/paste/:id", loginRequired, async (req, res) => {
    const paste = await prisma.paste({ id: req.params.id ? req.params.id : "" });
    if (paste) {
        const author = await prisma.paste({ id: paste.id }).author();
        const user = await prisma.user({ id: req.token.id });
        const id = paste.id;
        // if author or admin
        if (user.id === author.id || user.role === "ADMIN") {
            await prisma.deletePaste({ id });
            res.status(200).json({
                statusText: `${id} was deleted.`,
                paste
            });
        } else {
            res.status(403).json({
                statusText: "Not yo paste."
            });
        }
    } else {
        res.status(404).json({
            statusText: `No paste by that ID ${req.params.id}`
        });
    }
});

app.post("/api/v1/paste", loginRequired, async (req, res) => {
    const { content } = req.body;
    if (content) {
        const paste = await prisma.createPaste({
            content,
            author: {
                connect: { id: req.token.id }
            }
        });
        res.status(201).json({
            paste
        });
    } else {
        res.status(400).json({
            statusText: "Invalid form data"
        });
    }
});

// return a list of public pastes (priavte as well if user is admin)
app.get("/api/v1/pastes", loginRequired, async (req, res) => {
    let pastes;
    if (req.user.role === "USER") {
        // all public pastes
        pastes = await prisma.pastes({ where: { access: "PUBLIC" } });
    } else if (req.user.role === "ADMIN") {
        // all pastes
        pastes = await prisma.pastes();
    }

    res.json({
        statusText: "success",
        pastes: pastes
    });
});

// return a list of users (admin only)
app.get("/api/v1/users", [loginRequired, adminRequired], async (req, res) => {
    res.json({
        statuxText: "success",
        users: await prisma.users()
    });
});

app.get("/api/v1/user/:username", loginRequired, async (req, res) => {
    // if owner
    const user = await prisma.user({ username: req.params.username });
    console.log(user);
    if (!user) {
        res.status(400).json({
            statusText: "Invalid username",
        });
    } else if (req.user.username === req.params.username || req.user.role === "ADMIN") {
        res.json({
            statusText: "success",
            user: user
        });
    } else {
        res.json({
            statusText: "success",
            user: { username: user.username }
        });
    }
});

module.exports = app;
