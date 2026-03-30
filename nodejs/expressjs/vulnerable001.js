const express = require('express');
const fs = require('fs');
const { exec } = require('child_process');
const axios = require('axios');

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

app.listen(3000);
