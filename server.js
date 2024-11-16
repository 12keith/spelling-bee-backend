const express = require('express');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const app = express();
const PORT = 3000;
const SECRET_KEY = 'your-secret-key';  // Replace with a secure secret key
const Database = require('better-sqlite3');
const path = require('path');
const db = new Database(path.join(__dirname, 'database_folder', 'database.db'));

// Middleware
app.use(express.json()); // Parses incoming JSON requests

// Create tables if they don't exist
db.exec(`
    CREATE TABLE IF NOT EXISTS words (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        word TEXT NOT NULL,
        difficulty TEXT NOT NULL
    );

    CREATE TABLE IF NOT EXISTS scores (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT NOT NULL,
        score INTEGER NOT NULL
    );

    CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT NOT NULL UNIQUE,
        password TEXT NOT NULL
    );
`);

// Seed some sample words if they don't already exist
const words = [
    { word: "apple", difficulty: "easy" },
    { word: "banana", difficulty: "easy" },
    { word: "cherry", difficulty: "medium" }
];

words.forEach(word => {
    const existingWord = db.prepare('SELECT * FROM words WHERE word = ?').get(word.word);
    if (!existingWord) {
        db.prepare('INSERT INTO words (word, difficulty) VALUES (?, ?)').run(word.word, word.difficulty);
    }
});

// JWT authentication middleware
const verifyToken = (req, res, next) => {
    const token = req.headers['authorization'];

    if (!token) {
        return res.status(403).json({ error: 'No token provided' });
    }

    const bearerToken = token.split(' ')[1];  // This will get the actual token part

    if (!bearerToken) {
        return res.status(403).json({ error: 'Invalid token format' });
    }

    jwt.verify(bearerToken, SECRET_KEY, (err, decoded) => {
        if (err) {
            return res.status(403).json({ error: 'Failed to authenticate token' });
        }

        req.userId = decoded.id;
        req.username = decoded.username;
        next();
    });
};

// Root route to verify the server is running
app.get('/', (req, res) => {
    res.send('Welcome to the Spelling Bee Adventure API!');
});

// API endpoint to fetch words
app.get('/words', (req, res) => {
    const words = db.prepare('SELECT * FROM words').all();
    res.json(words);
});

// User Registration Endpoint
app.post('/register', async (req, res) => {
    const { username, password } = req.body;

    if (!username || !password) {
        return res.status(400).json({ error: 'Username and password are required' });
    }

    const existingUser = db.prepare('SELECT * FROM users WHERE username = ?').get(username);
    if (existingUser) {
        return res.status(400).json({ error: 'Username already exists' });
    }

    const hashedPassword = await bcrypt.hash(password, 10);

    db.prepare('INSERT INTO users (username, password) VALUES (?, ?)').run(username, hashedPassword);

    res.json({ message: 'User registered successfully' });
});

// User Login Endpoint
app.post('/login', async (req, res) => {
    const { username, password } = req.body;

    if (!username || !password) {
        return res.status(400).json({ error: 'Username and password are required' });
    }

    const user = db.prepare('SELECT * FROM users WHERE username = ?').get(username);
    if (!user) {
        return res.status(400).json({ error: 'Invalid username or password' });
    }

    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) {
        return res.status(400).json({ error: 'Invalid username or password' });
    }

    const token = jwt.sign({ id: user.id, username: user.username }, SECRET_KEY, { expiresIn: '1h' });

    res.json({ message: 'Login successful', token });
});

// Protected route to save score
app.post('/scores', verifyToken, (req, res) => {
    const { score } = req.body;
    const username = req.username;

    if (typeof score !== 'number') {
        return res.status(400).json({ error: 'Invalid input' });
    }

    db.prepare('INSERT INTO scores (username, score) VALUES (?, ?)').run(username, score);
    res.json({ message: 'Score saved successfully!' });
});

// Endpoint to get all scores
app.get('/scores', (req, res) => {
    const scores = db.prepare('SELECT * FROM scores ORDER BY score DESC').all();
    res.json(scores);
});

// Global error handler
app.use((err, req, res, next) => {
    console.error(err.stack);
    res.status(500).send('Something went wrong!');
});

// Start the server
app.listen(PORT, () => {
    console.log(`Server running on http://localhost:${PORT}`);
});



