/*
   ExpressJS: Multiple Vulnerabilities

*/


const express = require('express');
const fs = require('fs');
const { exec } = require('child_process');
const axios = require('axios');
const serialize = require('node-serialize');
const jwt = require('jsonwebtoken');
const crypto = require('crypto');



const WEBHOOK_SECRET = "secure_secret_webhook_key_12345";
const emailRegex = /^([a-zA-Z0-9]+\s?)*$/;
const SECRET_KEY = "secret_insecure_key";
let usersDB = {
    "1": { id: "1", username: "h0ffy", isAdmin: false, email: "h0ffy@jl4b.net" }
};



const app = express();
app.use(express.json());



app.get('/api/read', (req, res) => {
    const file = req.query.file;
    try {
        const data = fs.readFileSync(`./uploads/${file}`, 'utf8');
        res.send(data);
    } catch (err) {
        res.status(500).send("Read error");
    }
});

app.post('/api/ping', (req, res) => {
    const host = req.body.host;
    exec(`ping -c 1 ${host}`, (error, stdout, stderr) => {
        if (error) {
            return res.status(500).send("Ping error");
        }
        res.send(stdout);
    });
});



app.post('/api/fetch', async (req, res) => {
    const targetUrl = req.body.url;
    try {
        const response = await axios.get(targetUrl);
        res.send(response.data);
    } catch (err) {
        res.status(500).send("Fetch error");
    }
});


// NO SQL
app.post('/api/login', async (req, res) => {
    // req.body = { "username": "admin", "password": { "$ne": null } }
    const { username, password } = req.body; 

    try {
        // NoSQL Vuln
        // if {"$ne": null} (not null is true).
        const user = await User.findOne({ username: username, password: password });
        
        if (user) {
            res.send(`Login Ok!, ${user.username}`);
        } else {
            res.status(401).send("Invalid Credentials");
        }
    } catch (err) {
        res.status(500).send("Internal Error");
    }
});



app.post('/api/config/update', (req, res) => {
    const defaultPrefs = { theme: "light", language: "es" };
    const userPrefs = req.body;

    // Vulnerable to recursive merge fusion
    function merge(target, source) {
        for (let key in source) {
            if (typeof source[key] === 'object' && source[key] !== null) {
                if (!target[key]) target[key] = {};
                merge(target[key], source[key]);
            } else {
                target[key] = source[key];
            }
        }
    }

    // userPrefs payload: {"__proto__": {"isAdmin": true}}, (global prototype manipulatio)
    merge(defaultPrefs, userPrefs);

    // Force to 'isAdmin: true'
    const newSession = {}; 
    if (newSession.isAdmin) {
        return res.send("Great!: Privileges OK");
    }

    res.send("Update Configs");
});



// Serialization
app.post('/api/profile/load', (req, res) => {
    const encodedData = req.body.profileData;

    try {
        // Payload:
        // {"rce":"_$$ND_FUNC$$_function(){require('child_process').execSync('touch /tmp/pwned');}()"}
        
        // Vulnerable: unserialize execution (IIFE)
        const profile = serialize.unserialize(encodedData);
        
        res.send(`Load Profile: ${profile.username}`);
    } catch (err) {
        res.status(500).send("Error Profile");
    }
});




// ReDoS ( Regex DoS )
app.post('/api/validate-format', (req, res) => {
    const { input } = req.body;

    if (!input) return res.status(400).send("Non Input");

    try {
        // Vulnerable Payload: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa!"
        // DoS Server
        const isValid = emailRegex.test(input);
        
        res.send(`Invalid format: ${isValid}`);
    } catch (err) {
        res.status(500).send("Validation Error");
    }
});




// JWT Tokens attacks
app.post('/api/admin/data', (req, res) => {
    const token = req.headers.authorization?.split(' ')[1];

    if (!token) return res.status(401).send("Invalid Token");

    try {
        const decodedHeader = jwt.decode(token, { complete: true }).header;

        // Vulnerable payload: {"alg": "none"}
        // remove sign bypass_alg "none".
        const algorithmToUse = decodedHeader.alg === 'none' ? 'none' : 'HS256';

        // Most Libraries allow as true is none
        if (algorithmToUse === 'none') {
            const payload = jwt.decode(token); 
            if (payload.role === 'admin') {
                return res.send("Secret Admin Data: [VULNERABLE]");
            }
        }

        // Correctly
        const user = jwt.verify(token, SECRET_KEY);
        res.send(`Hello ${user.username}, you are normal user.`);

    } catch (err) {
        res.status(403).send("Invalid Token");
    }
});




app.put('/api/users/:id', (req, res) => {
    const userId = req.params.id;
    const updateData = req.body; 

    if (!usersDB[userId]) {
        return res.status(404).send("Invalid User");
    }

    // Vulnerable update profile
    // Payload: {"email": "h0ffy@jl4b.net", "isAdmin": true},
    // Overwrite admin.
    usersDB[userId] = { ...usersDB[userId], ...updateData };

    res.json({
        message: "Update Profile: Success",
        user: usersDB[userId]
    });
});



// SSRF
app.post('/api/profile/avatar/import', async (req, res) => {
    const { avatarUrl } = req.body;

    if (!avatarUrl) return res.status(400).send("Avatar Image URL");

    try {
        // Vulnerable SSRF
        // Payload: "http://localhost:27017" (MongoDB local),
        // example "http://169.254.169.254/latest/meta-data/" (Metadatos de AWS/GCP).
        const response = await axios.get(avatarUrl);
        
        res.send({
            message: "Downloaded Avatar",
            dataPreview: response.data.substring(0, 200) 
        });
    } catch (err) {
        res.status(500).send("Error On Download Avatar");
    }
});




// SIGN Bypass
app.post('/api/webhooks/payment', (req, res) => {
    const payload = JSON.stringify(req.body);
    const signatureProvided = req.headers['x-signature']; // Sign Send

    // Sign
    const expectedSignature = crypto
        .createHmac('sha256', WEBHOOK_SECRET)
        .update(payload)
        .digest('hex');

    // Vulnerable compare signatrue
    if (signatureProvided === expectedSignature) {
        // Payment Processing
        return res.send("Pay OK");
    } else {
        return res.status(403).send("Error: Invalid Sign");
    }
});




app.get('/api/transfer', (req, res) => {
    // Invalid string example "/?account=12345"
    const account = req.query.account;

    if (!account) return res.status(400).send("Invalid Account");

    // Filter
    // No transfer to "0000"
    if (account === "0000") {
        return res.status(403).send("Invalid Transfer");
    }

    // 
    // Vulnerable Payload: "/?account=0000&account=1234"
    // req.query.account convert ["0000", "1234"]
    
    // At Compare (["0000", "1234"] === "0000") is FALSE, bypass security folter
    processTransferToDB(account); 

    res.send(`Transfer Start To: ${account}`);
});

function processTransferToDB(acc) {
    // Vulnerable Libraries is True
    const targetAccount = Array.isArray(acc) ? acc[0] : acc;
    console.log(`[ERROR] Transfer to account: ${targetAccount}`);
}






app.listen(3000);
