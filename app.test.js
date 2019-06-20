const request = require("supertest");
const app = require("./app");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");

const { prisma } = require("./generated/prisma-client");
const config = require("./config");

describe("Test /api/v1/auth/signup", () => {
    describe("Method POST", () => {
        it("Should return 409 if username already taken", async (done) => {
            const user = await prisma.createUser({
                username: "jest-test",
                password: bcrypt.hashSync("jest-test", 10),
                email: "jest@test.com"
            });
            request(app).post("/api/v1/auth/signup")
                .send({ username: user.username, email: "some@fake.email", password: "hunter2" })
                .then((response) => {
                    expect(response.status).toBe(409);
                    expect(response.body.statusText).toEqual("Username taken");
                    done();
                });
        });
        it("Should return 409 if email already taken", async (done) => {
            const user = await prisma.createUser({
                username: "jest-test",
                password: bcrypt.hashSync("jest-test", 10),
                email: "jest@test.com"
            });
            request(app).post("/api/v1/auth/signup")
                .send({ username: "jest-test2", email: user.email, password: "hunter2" })
                .then((response) => {
                    expect(response.status).toBe(409);
                    expect(response.body.statusText).toEqual("Email taken");
                    done();
                });
        });
        it("Returns 400 with invalid data", (done) => {
            request(app).post("/api/v1/auth/signup")
                .send({})
                .then((response) => {
                    expect(response.status).toBe(400);
                    done();
                });
        });

        it("Returns 201 with valid data", (done) => {
            request(app).post("/api/v1/auth/signup")
                .send({ username: "jest-test", password: "jest-test", email: "jest@test.com" })
                .then((response) => {
                    expect(response.status).toBe(201);
                    done();
                });
        });

        it("Returns a valid user model after adding new user to database", (done) => {
            request(app).post("/api/v1/auth/signup")
                .send({ username: "jest-test", password: "jest-test", email: "jest@test.com" })
                .then((response) => {
                    expect(response.body.user).toEqual({
                        username: "jest-test",
                        // Should be bcrypt hash
                        password: expect.stringMatching(/^\$2[ayb]\$.{56}$/),
                        createdAt: expect.anything(),
                        id: expect.anything(),
                        role: "USER",
                        email: "jest@test.com"
                    });
                    done();
                });
        });
    });
});

describe("Test /api/v1/auth", () => {
    it("Should return 400 if invalid form data", async (done) => {
        request(app).post(`/api/v1/auth`)
            .send({})
            .then((response) => {
                expect(response.status).toBe(400);
                done();
            });
    });
    it("Should return status 401 on failed login (email)", async (done) => {
        request(app).post("/api/v1/auth")
            .send({ username: "**JEST TEST**", password: "LET ME IN!!!" })
            .then((response) => {
                expect(response.status).toBe(401);
                done();
            });
    });
    it("Should return status 401 on failed login (password)", async (done) => {
        const user = await prisma.createUser({
            username: "jest-test",
            password: bcrypt.hashSync("jest-test", 10),
            email: "jest@test.com"
        });
        request(app).post("/api/v1/auth")
            .send({ username: user.username, password: "LET ME IN!!!" })
            .then((response) => {
                expect(response.status).toBe(401);
                done();
            });
    });
    it("Should return a json web token on valid login", async (done) => {
        const username = "jest-test";
        const password = "jest-test";
        const email = "jest@test.com";
        await prisma.createUser({
            username,
            password: bcrypt.hashSync(password, 10),
            email
        });
        request(app).post("/api/v1/auth")
            .send({ username, password, email })
            .then((response) => {
                expect(response.body).toEqual({
                    statusText: expect.anything(),
                    token: expect.stringMatching(/^[A-Za-z0-9-_=]+\.[A-Za-z0-9-_=]+\.?[A-Za-z0-9-_.+/=]*$/)
                });
                done();
            });
    });
});

describe("Test /api/v1/paste", () => {
    describe("Method: POST", () => {
        it("Should return 400 when invalid form data is sent", async (done) => {
            const user = await prisma.createUser({
                username: "jest-test",
                password: bcrypt.hashSync("jest-test", 10),
                email: "jest@test.com"
            });
            request(app).post("/api/v1/paste")
                .set('Authorization', 'Bearer ' + jwt.sign({ id: user.id }, config.secert))
                .send({})
                .then((response) => {
                    expect(response.status).toBe(400);
                    done();
                });
        });
        it("Should return Paste if valid form data", async (done) => {
            const username = "jest-test";
            const password = "jest-test";
            const email = "jest@test.com";
            const user = await prisma.createUser({
                username,
                password: bcrypt.hashSync(password, 10),
                email
            });
            request(app).post("/api/v1/paste")
                .set('Authorization', 'Bearer ' + jwt.sign({ id: user.id }, config.secert))
                .send({ content: "[jest-test]" })
                .then((response) => {
                    expect(response.body).toEqual({
                        paste: {
                            id: expect.anything(),
                            content: "[jest-test]",
                            access: "PUBLIC",
                            createdAt: expect.anything()
                        }
                    });
                    done();
                });
        });
    });

    describe("Method: GET", () => {
        it("Should return 404 if invalid paste id", async (done) => {
            const user = await prisma.createUser({
                username: "jest-test",
                password: bcrypt.hashSync("jest-test", 10),
                email: "jest@test.com"
            });
            request(app).get(`/api/v1/paste/**FAKE ID**`)
                .set('Authorization', 'Bearer ' + jwt.sign({ id: user.id }, config.secert))
                .then((response) => {
                    expect(response.status).toBe(404);
                    done();
                });
        });
        it("Should return Paste if `id` valid", async (done) => {
            const user = await prisma.createUser({
                username: "jest-test",
                password: bcrypt.hashSync("jest-test", 10),
                email: "jest@test.com"
            });
            const paste = await prisma.createPaste({
                content: "[jest-test]", author: {
                    connect: { id: user.id }
                }
            });
            request(app).get(`/api/v1/paste/${paste.id}`)
                .then((response) => {
                    expect(response.body).toEqual({
                        statusText: expect.anything(),
                        paste: {
                            id: expect.anything(),
                            content: expect.anything(),
                            createdAt: expect.anything(),
                            access: expect.anything()
                        }
                    });
                    done();
                });
        });
    });

    describe("Method: DELETE", () => {
        it("Should delete paste", async (done) => {
            const username = "jest-test";
            const password = "jest-test";
            const email = "jest@test.com";
            const user = await prisma.createUser({
                username,
                password: bcrypt.hashSync(password, 10),
                email
            });
            const paste = await prisma.createPaste({
                content: "[jest-test]", author: {
                    connect: { id: user.id }
                }
            });
            request(app).delete(`/api/v1/paste/${paste.id}`)
                .set('Authorization', 'Bearer ' + jwt.sign({ id: user.id }, config.secert))
                .then((response) => {
                    expect(response.status).toBe(200);
                    expect(response.body).toEqual({
                        statusText: expect.anything(),
                        paste: expect.anything()
                    });
                    done();
                });
        });
        it("Should return 404 if invalid paste id", async (done) => {
            const user = await prisma.createUser({
                username: "jest-test",
                password: bcrypt.hashSync("jest-test", 10),
                email: "jest@test.com"
            });
            request(app).delete(`/api/v1/paste/**FAKE ID**`)
                .set('Authorization', 'Bearer ' + jwt.sign({ id: user.id }, config.secert))
                .then((response) => {
                    expect(response.status).toBe(404);
                    done();
                });
        });
        it("Should return 403 if user tries to delete a paste they don't own", async (done) => {
            const user = await prisma.createUser({
                username: "jest-test",
                password: bcrypt.hashSync("jest-test", 10),
                email: "jest@test.com"
            });
            const user2 = await prisma.createUser({
                username: "jest-test2",
                password: bcrypt.hashSync("jest-test2", 10),
                email: "jest@test.com2"
            });
            const paste = await prisma.createPaste({
                content: "[jest-test]", author: {
                    connect: { id: user.id }
                }
            });
            request(app).delete(`/api/v1/paste/${paste.id}`)
                .set('Authorization', 'Bearer ' + jwt.sign({ id: user2.id }, config.secert))
                .then(async (response) => {
                    expect(response.status).toBe(403);
                    // clean up
                    await prisma.deleteUser({ id: user2.id });
                    done();
                });
        });
        it("Should allow admin to delete anyones post", async (done) => {
            const user = await prisma.createUser({
                username: "jest-test",
                password: bcrypt.hashSync("jest-test", 10),
                email: "jest@test.com"
            });
            const admin = await prisma.createUser({
                username: "jest-test-admin",
                password: bcrypt.hashSync("jest-test-admin", 10),
                email: "jest@admin.test.com",
                role: "ADMIN"
            });
            const paste = await prisma.createPaste({
                content: "[jest-test]", author: {
                    connect: { id: user.id }
                }
            });
            request(app).delete(`/api/v1/paste/${paste.id}`)
                .set('Authorization', 'Bearer ' + jwt.sign({ id: admin.id }, config.secert))
                .then(async (response) => {
                    expect(response.status).toBe(200);
                    // clean up
                    await prisma.deleteUser({ id: admin.id });
                    done();
                });
        });
    });
});

describe("Test /api/v1/pastes", () => {
    it("Should return all public paste as a normal user", async (done) => {
        const username = "jest-test";
        const password = "jest-test";
        const email = "jest@test.com";
        const user = await prisma.createUser({
            username,
            password: bcrypt.hashSync(password, 10),
            email
        });
        const publicPaste = await prisma.createPaste({
            content: "[jest-test]",
            author: {
                connect: { id: user.id }
            },
            access: "PUBLIC"
        });
        const privatePaste = await prisma.createPaste({
            content: "[jest-test]",
            author: {
                connect: { id: user.id }
            },
            access: "PRIVATE"
        });
        request(app).get("/api/v1/pastes")
            .set('Authorization', 'Bearer ' + jwt.sign({ id: user.id }, config.secert))
            .then((response) => {
                expect(response.status).toBe(200);
                expect(response.body).toEqual({
                    statusText: expect.anything(),
                    pastes: expect.arrayContaining([publicPaste])
                });
                expect(response.body).toEqual({
                    statusText: expect.anything(),
                    pastes: expect.not.arrayContaining([privatePaste])
                });
                done();
            });
    });
    it("Should return all paste as an admin user", async (done) => {
        const username = "jest-test";
        const password = "jest-test";
        const email = "jest@test.com";
        const admin = await prisma.createUser({
            username,
            password: bcrypt.hashSync(password, 10),
            email,
            role: "ADMIN"
        });
        const publicPaste = await prisma.createPaste({
            content: "[jest-test]",
            author: {
                connect: { id: admin.id }
            },
            access: "PUBLIC"
        });
        const privatePaste = await prisma.createPaste({
            content: "[jest-test]",
            author: {
                connect: { id: admin.id }
            },
            access: "PRIVATE"
        });
        request(app).get("/api/v1/pastes")
            .set('Authorization', 'Bearer ' + jwt.sign({ id: admin.id }, config.secert))
            .then((response) => {
                expect(response.status).toBe(200);
                expect(response.body).toEqual({
                    statusText: expect.anything(),
                    pastes: expect.arrayContaining([publicPaste, privatePaste])
                });
                done();
            });
    });
});

describe("Test /api/v1/users", () => {
    it("Should return 403 is user is not admin", async (done) => {
        const username = "jest-test";
        const password = "jest-test";
        const email = "jest@test.com";
        const user = await prisma.createUser({
            username,
            password: bcrypt.hashSync(password, 10),
            email,
        });
        request(app).get("/api/v1/users")
            .set('Authorization', 'Bearer ' + jwt.sign({ id: user.id }, config.secert))
            .then((response) => {
                expect(response.status).toBe(403);
                done();
            });
    });
    it("Should return a list of all users if user is admin", async (done) => {
        const username = "jest-test";
        const password = "jest-test";
        const email = "jest@test.com";
        const admin = await prisma.createUser({
            username,
            password: bcrypt.hashSync(password, 10),
            email,
            role: "ADMIN"
        });
        request(app).get("/api/v1/users")
            .set('Authorization', 'Bearer ' + jwt.sign({ id: admin.id }, config.secert))
            .then((response) => {
                expect(response.status).toBe(200);
                expect(Array.isArray(response.body.users)).toBe(true);
                done();
            });
    });
});

describe("Test /api/v1/user/:username", () => {
    it("Should return user data if username equals user", async (done) => {
        const user = await prisma.createUser({
            username: "jest-test",
            password: bcrypt.hashSync("jest-test", 10),
            email: "jest@test.com"
        });
        request(app).get(`/api/v1/user/${user.username}`)
            .set('Authorization', 'Bearer ' + jwt.sign({ id: user.id }, config.secert))
            .then((response) => {
                expect(response.status).toBe(200);
                expect(response.body).toEqual({
                    statusText: expect.anything(),
                    user: user
                });
                done();
            });
    });
    it("Should return user data if admin", async (done) => {
        const user = await prisma.createUser({
            username: "jest-test",
            password: bcrypt.hashSync("jest-test", 10),
            email: "jest@test.com"
        });
        const admin = await prisma.createUser({
            username: "jest-test-admin",
            password: bcrypt.hashSync("jest-test-admin", 10),
            email: "jest@admin.test.com",
            role: "ADMIN"
        });
        request(app).get(`/api/v1/user/${user.username}`)
            .set('Authorization', 'Bearer ' + jwt.sign({ id: admin.id }, config.secert))
            .then((response) => {
                expect(response.status).toBe(200);
                expect(response.body).toEqual({
                    statusText: expect.anything(),
                    user: user
                });
                done();
            });
    });
    it("Should return username only if not admin or user", async (done) => {
        const user = await prisma.createUser({
            username: "jest-test",
            password: bcrypt.hashSync("jest-test", 10),
            email: "jest@test.com"
        });
        const user2 = await prisma.createUser({
            username: "jest-test-admin",
            password: bcrypt.hashSync("jest-test-admin", 10),
            email: "jest@admin.test.com",
        });
        request(app).get(`/api/v1/user/${user.username}`)
            .set('Authorization', 'Bearer ' + jwt.sign({ id: user2.id }, config.secert))
            .then((response) => {
                expect(response.status).toBe(200);
                expect(response.body).toEqual({
                    statusText: expect.anything(),
                    user: {
                        username: expect.anything()
                    }
                });
                done();
            });
    });
    it("Should return 400 when invalid username", async (done) => {
        const user = await prisma.createUser({
            username: "jest-test",
            password: bcrypt.hashSync("jest-test", 10),
            email: "jest@test.com"
        });
        request(app).get("/api/v1/user/***fake user***")
            .set('Authorization', 'Bearer ' + jwt.sign({ id: user.id }, config.secert))
            .then((response) => {
                expect(response.status).toBe(400);
                done();
            });
    });
});

beforeEach(async () => {
    await prisma.deleteManyPastes({ content: "[jest-test]" });
    const user = await prisma.user({ username: "jest-test" });
    const admin = await prisma.user({ username: "jest-test-admin" });
    if (user) {
        await prisma.deleteUser({ username: "jest-test" });
    }
    if (admin) {
        await prisma.deleteUser({ username: "jest-test-admin" });
    }
});

afterEach(async () => {
    await prisma.deleteManyPastes({ content: "[jest-test]" });
    const user = await prisma.user({ username: "jest-test" });
    const admin = await prisma.user({ username: "jest-test-admin" });
    if (user) {
        await prisma.deleteUser({ username: "jest-test" });
    }
    if (admin) {
        await prisma.deleteUser({ username: "jest-test-admin" });
    }
});