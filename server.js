const express = require("express");
const sqlite3 = require("sqlite3").verbose();
const bcrypt = require("bcrypt");
const session = require("express-session");
const multer = require("multer");
const path = require("path");
const fs = require("fs");

const app = express();
const PORT = 3000;

// BUG FIX #1: Auto-create uploads folder so multer never crashes
fs.mkdirSync("uploads", { recursive: true });

// Middleware
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

app.use(
    session({
        secret: process.env.SESSION_SECRET || "my_blog_secret_key",
        resave: false,
        saveUninitialized: false,
        cookie: { httpOnly: true }
    })
);

app.use(express.static("public"));
app.use("/uploads", express.static("uploads"));

// Database
const db = new sqlite3.Database("blog.db");

db.serialize(() => {
    db.run(`
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL
        )
    `);

    db.run(`
        CREATE TABLE IF NOT EXISTS posts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            title TEXT NOT NULL,
            content TEXT NOT NULL,
            image TEXT,
            user_id INTEGER NOT NULL,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (user_id) REFERENCES users(id)
        )
    `);
});

// Image Upload Setup
const storage = multer.diskStorage({
    destination: function (req, file, cb) {
        cb(null, "uploads/");
    },
    filename: function (req, file, cb) {
        const ext = path.extname(file.originalname);
        cb(null, Date.now() + "-" + Math.random().toString(36).slice(2) + ext);
    }
});

const upload = multer({
    storage,
    limits: { fileSize: 5 * 1024 * 1024 }, // 5MB max
    fileFilter: (req, file, cb) => {
        const allowed = /jpeg|jpg|png|gif|webp/;
        const ok = allowed.test(file.mimetype) && allowed.test(path.extname(file.originalname).toLowerCase());
        ok ? cb(null, true) : cb(new Error("Only image files are allowed"));
    }
});

// ─── Auth Routes ────────────────────────────────────────────────────────────

app.post("/register", async (req, res) => {
    const { username, password } = req.body;

    // BUG FIX: Input validation
    if (!username || !password || username.trim().length < 3 || password.length < 6) {
        return res.status(400).json({
            error: "Username must be 3+ chars and password 6+ chars"
        });
    }

    try {
        const hashedPassword = await bcrypt.hash(password, 10);

        db.run(
            "INSERT INTO users(username, password) VALUES(?, ?)",
            [username.trim(), hashedPassword],
            function (err) {
                if (err) {
                    return res.status(400).json({ error: "Username already taken" });
                }
                res.json({ success: true, message: "Account created" });
            }
        );
    } catch (error) {
        res.status(500).json({ error: "Server error" });
    }
});

app.post("/login", (req, res) => {
    const { username, password } = req.body;

    if (!username || !password) {
        return res.status(400).json({ error: "All fields are required" });
    }

    db.get(
        "SELECT * FROM users WHERE username = ?",
        [username.trim()],
        async (err, user) => {
            // BUG FIX #2: err was never checked in the original
            if (err) {
                return res.status(500).json({ error: "Database error" });
            }

            if (!user) {
                return res.status(401).json({ error: "Invalid username or password" });
            }

            const match = await bcrypt.compare(password, user.password);

            if (!match) {
                // BUG FIX: Don't reveal which field is wrong (security best practice)
                return res.status(401).json({ error: "Invalid username or password" });
            }

            req.session.userId = user.id;
            req.session.username = user.username;

            res.json({ success: true, username: user.username });
        }
    );
});

app.get("/logout", (req, res) => {
    req.session.destroy(() => {
        res.redirect("/login.html");
    });
});

app.get("/me", (req, res) => {
    if (!req.session.userId) {
        return res.json({ loggedIn: false });
    }
    res.json({ loggedIn: true, username: req.session.username });
});

// ─── Post Routes ─────────────────────────────────────────────────────────────

app.post("/posts", upload.single("image"), (req, res) => {
    if (!req.session.userId) {
        return res.status(401).json({ error: "Login required" });
    }

    const { title, content } = req.body;

    // BUG FIX: Validate post fields
    if (!title || !content || title.trim().length === 0 || content.trim().length === 0) {
        return res.status(400).json({ error: "Title and content are required" });
    }

    const image = req.file ? req.file.filename : null;

    db.run(
        `INSERT INTO posts (title, content, image, user_id) VALUES (?, ?, ?, ?)`,
        [title.trim(), content.trim(), image, req.session.userId],
        function (err) {
            if (err) {
                return res.status(500).json({ error: "Failed to create post" });
            }
            res.json({ success: true, postId: this.lastID });
        }
    );
});

app.get("/posts", (req, res) => {
    db.all(
        `SELECT posts.*, users.username
         FROM posts
         JOIN users ON posts.user_id = users.id
         ORDER BY posts.id DESC`,
        [],
        (err, rows) => {
            if (err) {
                return res.status(500).json({ error: "Failed to fetch posts" });
            }
            res.json(rows);
        }
    );
});

app.delete("/posts/:id", (req, res) => {
    if (!req.session.userId) {
        return res.status(401).json({ error: "Login required" });
    }

    const postId = req.params.id;

    db.get("SELECT * FROM posts WHERE id = ?", [postId], (err, post) => {
        // BUG FIX #3: err from db.get was never checked
        if (err) {
            return res.status(500).json({ error: "Database error" });
        }

        if (!post) {
            return res.status(404).json({ error: "Post not found" });
        }

        if (post.user_id !== req.session.userId) {
            return res.status(403).json({ error: "You can only delete your own posts" });
        }

        db.run("DELETE FROM posts WHERE id = ?", [postId], (err) => {
            // BUG FIX #4: DELETE db.run error was never handled
            if (err) {
                return res.status(500).json({ error: "Failed to delete post" });
            }

            // Clean up uploaded image if exists
            if (post.image) {
                fs.unlink(path.join("uploads", post.image), () => {});
            }

            res.json({ success: true });
        });
    });
});

// Global error handler for multer and others
app.use((err, req, res, next) => {
    if (err.message === "Only image files are allowed") {
        return res.status(400).json({ error: err.message });
    }
    if (err.code === "LIMIT_FILE_SIZE") {
        return res.status(400).json({ error: "Image must be under 5MB" });
    }
    res.status(500).json({ error: "Server error" });
});

app.listen(PORT, "0.0.0.0", () => {
    console.log(`Server running → http://0.0.0.0:${PORT}`);
});