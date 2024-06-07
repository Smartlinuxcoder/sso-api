const express = require('express');
const bodyParser = require('body-parser');
const crypto = require('crypto');
const sqlite3 = require('sqlite3').verbose();
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const fs = require('fs');
require('dotenv').config();
const cors = require('cors');


const jwtSecret = process.env.JWT_SECRET;



const app = express();
app.use(bodyParser.json());
app.use(cors());
// Inizializza il database SQLite3
const db = new sqlite3.Database('users.db');

// Crea la tabella degli utenti se non esiste
db.serialize(() => {
  db.run(`CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE,
    password TEXT
  )`);
  db.run(`CREATE TABLE IF NOT EXISTS sites (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    site TEXT UNIQUE,
    password TEXT
  )`);
});

function generateSalt(length) {
    return crypto.randomBytes(Math.ceil(length / 2))
        .toString('hex') // Convert to hexadecimal format
        .slice(0, length); // Trim to desired length

}

function generateHash(data) {
    return crypto.createHash('sha256').update(data).digest('hex');
    
}
// Genera un token casuale

const authenticateToken = (req, res, next) => {
    const token = req.headers['authorization'];
    if (!token) {
        return res.status(401).send("Access denied. Token missing.");
    }
    jwt.verify(token, jwtSecret, (err, user) => {
        if (err || !user) {
            return res.status(403).send("Access denied. Invalid token.");
        }
        req.user = user;
        next();
    });
};
// API per l'autenticazione e il recupero del token
app.post('/api/register', async (req, res) => {
    try {
        const { username, password } = req.body;
        const hashedPassword = await bcrypt.hash(password, 10);
        db.run("INSERT INTO users (username, password) VALUES (?, ?)", [username, hashedPassword], function (err) {
            if (err) {
                console.error(err);
                return res.status(400).send("Username already exists");
            }
            res.status(201).send("User registered successfully");
        });
    } catch (error) {
        console.error(error);
        res.status(500).send("Error registering user");
    }
});

app.post('/api/login', async (req, res) => {
    try {
        const { username, password, site } = req.body;
        db.get("SELECT * FROM users WHERE username = ?", [username], async (err, row) => {
            if (err) {
                console.error(err);
                return res.status(500).send("Error logging in");
            }
            if (!row) {
                return res.status(400).send("Invalid username or password");
            }
            const isValidPassword = await bcrypt.compare(password, row.password);
            if (!isValidPassword) {
                return res.status(400).send("Invalid username or password");
            }
            const token = jwt.sign({ username: row.username }, jwtSecret);
            const timestamp = Date.now();
            const salt = generateSalt(16);
            const session = `${site}--${token}--${username}--${timestamp}--${salt}`;
            const hash = generateHash(session);
            const filePath = `sessions/${hash}.txt`;
            fs.writeFileSync(filePath, session);
            setTimeout(() => {
                fs.unlinkSync(filePath);
            }, 10 * 60 * 1000); // 10 minutes in milliseconds
            res.status(200).json({ hash });
        });
    } catch (error) {
        console.error(error);
        res.status(500).send("Error logging in");
    }
});

app.post('/api/site/register', async (req, res) => {
    try {
        const { site, password } = req.body;
        const hashedPassword = await bcrypt.hash(password, 10);
        db.run("INSERT INTO sites (site, password) VALUES (?, ?)", [site, hashedPassword], function (err) {
            if (err) {
                console.error(err);
                return res.status(400).send("Username already exists");
            }
            res.status(201).send("User registered successfully");
        });
    } catch (error) {
        console.error(error);
        res.status(500).send("Error registering user");
    }
});

app.post('/api/site/login', async (req, res) => {
    try {
        const { site, password } = req.body;
        db.get("SELECT * FROM sites WHERE site = ?", [site], async (err, row) => {
            if (err) {
                console.error(err);
                return res.status(500).send("Error logging in");
            }
            if (!row) {
                return res.status(400).send("Invalid username or password");
            }
            const isValidPassword = await bcrypt.compare(password, row.password);
            console.log(password)
            console.log(row.password)
            if (!isValidPassword) {
                return res.status(400).send("Invalid username or password");
            }
            const token = jwt.sign({ site: row.site }, jwtSecret);
            res.status(200).json({ token });
        });
    } catch (error) {
        console.error(error);
        res.status(500).send("Error logging in");
    }
});

app.post('/api/site/secureaccess', async (req, res) => {
    try {
        const { site, password, sessiontoken } = req.body;
        db.get("SELECT * FROM sites WHERE site = ?", [site], async (err, row) => {
            if (err) {
                console.error(err);
                return res.status(500).send("Error logging in");
            }
            if (!row) {
                return res.status(400).send("Invalid username or password");
            }
            const isValidPassword = await bcrypt.compare(password, row.password);
            if (!isValidPassword) {
                return res.status(400).send("Invalid username or password");
            }
            const token = jwt.sign({ site: row.site }, jwtSecret);
            const filePath = `sessions/${sessiontoken}.txt`;
            const data = fs.readFileSync(filePath, 'utf8');
            const parts = data.split('--');
            const website = req.body.site
            if (website !== parts[0]) {

                return res.status(403).send("Access denied. Invalid token.");
            }
            const username = parts[2];
            res.status(200).json({ username });
        });
    } catch (error) {
        console.error(error);
        res.status(500).send("Error logging in");
    }
});

app.post('/api/writeJson', (req, res) => {
    try {
        const { sessiontoken, website, data } = req.body;
        const sessionpath = `sessions/${sessiontoken}.txt`;
        const sessionfile = fs.readFileSync(sessionpath, 'utf8');
        const parts = sessionfile.split('--');
        const username = parts[2];
        const filePath =`usercontent/${username}.json`;

        // Read existing data from JSON file or create an empty object
        let jsonData = {};
        try {
            const existingData = fs.readFileSync(filePath);
            jsonData = JSON.parse(existingData);
        } catch (err) {
            // File doesn't exist or couldn't be read
            console.error("Error reading JSON file:", err);
        }
        if (website !== parts[0]) {

            return res.status(403).send("Access denied. Invalid token.");
        }
        // Update or add data for the website
        jsonData[website] = data;

        // Write updated data to JSON file
        fs.writeFile(filePath, JSON.stringify(jsonData, null, 2), (err) => {
            if (err) {
                console.error(err);
                return res.status(500).send("Error writing to JSON file");
            }

            res.status(200).send(`Data written to ${username}.json under ${website} successfully`);
        });
    } catch (error) {
        console.error(error);
        res.status(500).send("Error writing to JSON file");
    }
});


const mergeDeep = (target, source) => {
    for (const key of Object.keys(source)) {
        if (source[key] instanceof Object && key in target) {
            Object.assign(source[key], mergeDeep(target[key], source[key]));
        }
    }
    return { ...target, ...source };
};

app.post('/api/updateJson', (req, res) => {
    try {
        const { sessiontoken, website, data } = req.body;
        const sessionpath = `sessions/${sessiontoken}.txt`;
        const sessionfile = fs.readFileSync(sessionpath, 'utf8');
        const parts = sessionfile.split('--');
        const username = parts[2];
        const filePath = `usercontent/${username}.json`;

        // Read existing data from JSON file or create an empty object
        let jsonData = {};
        try {
            const existingData = fs.readFileSync(filePath);
            jsonData = JSON.parse(existingData);
        } catch (err) {
            if (err.code === 'ENOENT') {
                // File doesn't exist, initialize jsonData
                jsonData = {};
            } else {
                console.error("Error reading JSON file:", err);
                return res.status(500).send("Error reading JSON file");
            }
        }

        if (website !== parts[0]) {
            return res.status(403).send("Access denied. Invalid token.");
        }

        // Merge incoming data with existing data
        if (!jsonData[website]) {
            jsonData[website] = data;
        } else {
            jsonData[website] = mergeDeep(jsonData[website], data);
        }

        // Write updated data to JSON file
        fs.writeFile(filePath, JSON.stringify(jsonData, null, 2), (err) => {
            if (err) {
                console.error(err);
                return res.status(500).send("Error writing to JSON file");
            }

            res.status(200).send(`Data updated in ${username}.json under ${website} successfully`);
        });
    } catch (error) {
        console.error(error);
        res.status(500).send("Error updating JSON file");
    }
});



app.post('/api/readJson', (req, res) => {
    try {
        const { sessiontoken, website } = req.body;
        const sessionpath = `sessions/${sessiontoken}.txt`;
        const sessionfile = fs.readFileSync(sessionpath, 'utf8');
        const parts = sessionfile.split('--');
        const username = parts[2];
        const filePath = `usercontent/${username}.json`;
        // Read data from JSON file
        fs.readFile(filePath, (err, data) => {
            if (err) {
                console.error(err);
                return res.status(500).send("Error reading JSON file");
            }
            try {
                const jsonData = JSON.parse(data);
                const websiteData = jsonData[website];
                if (!websiteData) {
                    return res.status(404).send("Website data not found");
                }

                res.status(200).json(websiteData);
            } catch (parseError) {
                console.error(parseError);
                res.status(500).send("Error parsing JSON data");
            }
        });
    } catch (error) {
        console.error(error);
        res.status(500).send("Error reading JSON file");
    }
});




const PORT = 3333;
app.listen(PORT, () => console.log(`Server in ascolto sulla porta ${PORT}`));
