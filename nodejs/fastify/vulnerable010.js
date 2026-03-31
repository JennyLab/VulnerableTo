/*
   Fastify: Multiple Vulnerabilities (CTF)
   Dependencies:
   npm install fastify axios jsonwebtoken node-serialize
*/

const fastify = require('fastify')({ logger: true });
const fs = require('fs');
const { exec } = require('child_process');
const axios = require('axios');
const serialize = require('node-serialize');
const jwt = require('jsonwebtoken');
const crypto = require('crypto');

// --- Configuraciones y Base de Datos Simulada ---
const WEBHOOK_SECRET = "secure_secret_webhook_key_12345";
const emailRegex = /^([a-zA-Z0-9]+\s?)*$/;
const SECRET_KEY = "secret_insecure_key";

let usersDB = {
    "1": { id: "1", username: "h0ffy", isAdmin: false, email: "h0ffy@jl4b.net" }
};


// 1. Path Traversal / LFI
fastify.get('/api/read', (request, reply) => {
    const file = request.query.file;
    try {
        const data = fs.readFileSync(`./uploads/${file}`, 'utf8');
        reply.send(data);
    } catch (err) {
        reply.code(500).send("Read error");
    }
});


// 2. Command Injection (RCE)
fastify.post('/api/ping', (request, reply) => {
    const host = request.body.host;
    // VULNERABLE: El payload viaja directo a la terminal
    exec(`ping -c 1 ${host}`, (error, stdout, stderr) => {
        if (error) {
            return reply.code(500).send("Ping error");
        }
        reply.send(stdout);
    });
});


// 3. SSRF Básico
fastify.post('/api/fetch', async (request, reply) => {
    const targetUrl = request.body.url;
    try {
        const response = await axios.get(targetUrl);
        reply.send(response.data);
    } catch (err) {
        reply.code(500).send("Fetch error");
    }
});


// 4. NoSQL Injection (Simulado)
fastify.post('/api/login', async (request, reply) => {
    // Payload: { "username": "admin", "password": { "$ne": null } }
    const { username, password } = request.body; 

    try {
        // Simulación de un motor NoSQL vulnerable
        // Si password es un objeto {"$ne": null}, evalúa a true.
        const isPasswordNotEqualNull = typeof password === 'object' && password['$ne'] === null;
        
        if (username === 'admin' && (password === 'admin123' || isPasswordNotEqualNull)) {
            reply.send(`Login Ok!, ${username}`);
        } else {
            reply.code(401).send("Invalid Credentials");
        }
    } catch (err) {
        reply.code(500).send("Internal Error");
    }
});


// 5. Prototype Pollution / Recursive Merge
fastify.post('/api/config/update', (request, reply) => {
    const defaultPrefs = { theme: "light", language: "es" };
    const userPrefs = request.body;

    // Vulnerable a fusión recursiva
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

    // Payload: {"__proto__": {"isAdmin": true}}
    merge(defaultPrefs, userPrefs);

    const newSession = {}; 
    if (newSession.isAdmin) {
        return reply.send("Great!: Privileges OK");
    }

    reply.send("Update Configs");
});


// 6. Insecure Deserialization (RCE)
fastify.post('/api/profile/load', (request, reply) => {
    const encodedData = request.body.profileData;

    try {
        // Payload: {"rce":"_$$ND_FUNC$$_function(){require('child_process').execSync('touch /tmp/pwned');}()"}
        const profile = serialize.unserialize(encodedData);
        reply.send(`Load Profile: ${profile.username}`);
    } catch (err) {
        reply.code(500).send("Error Profile");
    }
});


// 7. ReDoS (Regular Expression Denial of Service)
fastify.post('/api/validate-format', (request, reply) => {
    const input = request.body.input;

    if (!input) return reply.code(400).send("Non Input");

    try {
        // Payload: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa!"
        const isValid = emailRegex.test(input);
        reply.send(`Invalid format: ${isValid}`);
    } catch (err) {
        reply.code(500).send("Validation Error");
    }
});


// 8. JWT "alg: none" Bypass
fastify.post('/api/admin/data', (request, reply) => {
    const token = request.headers.authorization?.split(' ')[1];

    if (!token) return reply.code(401).send("Invalid Token");

    try {
        const decodedToken = jwt.decode(token, { complete: true });
        if (!decodedToken) throw new Error();

        const decodedHeader = decodedToken.header;
        const algorithmToUse = decodedHeader.alg === 'none' ? 'none' : 'HS256';

        // Vulnerabilidad: Aceptar "none"
        if (algorithmToUse === 'none') {
            const payload = jwt.decode(token); 
            if (payload.role === 'admin') {
                return reply.send("Secret Admin Data: [VULNERABLE]");
            }
        }

        const user = jwt.verify(token, SECRET_KEY);
        reply.send(`Hello ${user.username}, you are normal user.`);

    } catch (err) {
        reply.code(403).send("Invalid Token");
    }
});


// 9. Mass Assignment (Asignación Masiva)
fastify.put('/api/users/:id', (request, reply) => {
    const userId = request.params.id;
    const updateData = request.body; 

    if (!usersDB[userId]) {
        return reply.code(404).send("Invalid User");
    }

    // Payload: {"email": "hacker@jl4b.net", "isAdmin": true}
    usersDB[userId] = { ...usersDB[userId], ...updateData };

    reply.send({
        message: "Update Profile: Success",
        user: usersDB[userId]
    });
});


// 10. SSRF en importación de Avatar
fastify.post('/api/profile/avatar/import', async (request, reply) => {
    const avatarUrl = request.body.avatarUrl;

    if (!avatarUrl) return reply.code(400).send("Avatar Image URL required");

    try {
        // Payload: "http://169.254.169.254/latest/meta-data/"
        const response = await axios.get(avatarUrl);
        
        reply.send({
            message: "Downloaded Avatar",
            dataPreview: response.data.substring(0, 200) 
        });
    } catch (err) {
        reply.code(500).send("Error On Download Avatar");
    }
});


// 11. HMAC Signature Bypass (Timing/Type confusion)
fastify.post('/api/webhooks/payment', (request, reply) => {
    const payload = JSON.stringify(request.body);
    const signatureProvided = request.headers['x-signature']; 

    const expectedSignature = crypto
        .createHmac('sha256', WEBHOOK_SECRET)
        .update(payload)
        .digest('hex');

    // Vulnerabilidad: Comparación directa `===`
    if (signatureProvided === expectedSignature) {
        return reply.send("Pay OK");
    } else {
        return reply.code(403).send("Error: Invalid Sign");
    }
});


// 12. HTTP Parameter Pollution (HPP) / Type Confusion
fastify.get('/api/transfer', (request, reply) => {
    const account = request.query.account;

    if (!account) return reply.code(400).send("Invalid Account");

    // Fastify parsea "?account=0000&account=1234" como un array ["0000", "1234"]
    // Al comparar el array con el string, devuelve false y elude el bloqueo.
    if (account === "0000") {
        return reply.code(403).send("Invalid Transfer");
    }

    processTransferToDB(account); 

    reply.send(`Transfer Start To: ${account}`);
});

function processTransferToDB(acc) {
    const targetAccount = Array.isArray(acc) ? acc[0] : acc;
    fastify.log.error(`[ERROR] Transfer to account: ${targetAccount}`);
}


// --- Inicialización del Servidor ---
const start = async () => {
    try {
        await fastify.listen({ port: 3000 });
        fastify.log.info(`Servidor Fastify vulnerable escuchando en ${fastify.server.address().port}`);
    } catch (err) {
        fastify.log.error(err);
        process.exit(1);
    }
};

start();
