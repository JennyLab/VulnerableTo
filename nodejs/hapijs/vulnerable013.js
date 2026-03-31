/*
   HApi.js: Multiple Vulnerabilities (CTF)
   Dependencies:
   npm install @hapi/hapi axios jsonwebtoken node-serialize
*/

const Hapi = require('@hapi/hapi');
const fs = require('fs');
const util = require('util');
const { exec } = require('child_process');
const execPromise = util.promisify(exec); // Hapi prefiere async/await para los handlers
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

const init = async () => {
    const server = Hapi.server({
        port: 3000,
        host: 'localhost'
    });

    // 1. Path Traversal / LFI
    server.route({
        method: 'GET',
        path: '/api/read',
        handler: (request, h) => {
            const file = request.query.file;
            try {
                const data = fs.readFileSync(`./uploads/${file}`, 'utf8');
                return data;
            } catch (err) {
                return h.response("Read error").code(500);
            }
        }
    });

    // 2. Command Injection (RCE)
    server.route({
        method: 'POST',
        path: '/api/ping',
        handler: async (request, h) => {
            const host = request.payload.host;
            try {
                // VULNERABLE: El payload viaja directo a la terminal
                const { stdout } = await execPromise(`ping -c 1 ${host}`);
                return stdout;
            } catch (error) {
                return h.response("Ping error").code(500);
            }
        }
    });

    // 3. SSRF Básico
    server.route({
        method: 'POST',
        path: '/api/fetch',
        handler: async (request, h) => {
            const targetUrl = request.payload.url;
            try {
                const response = await axios.get(targetUrl);
                return response.data;
            } catch (err) {
                return h.response("Fetch error").code(500);
            }
        }
    });

    // 4. NoSQL Injection (Simulado)
    server.route({
        method: 'POST',
        path: '/api/login',
        handler: async (request, h) => {
            // Payload: { "username": "admin", "password": { "$ne": null } }
            const { username, password } = request.payload; 

            try {
                // Simulación de NoSQL Vuln
                const isPasswordNotEqualNull = typeof password === 'object' && password['$ne'] === null;
                
                if (username === 'admin' && (password === 'admin123' || isPasswordNotEqualNull)) {
                    return `Login Ok!, ${username}`;
                } else {
                    return h.response("Invalid Credentials").code(401);
                }
            } catch (err) {
                return h.response("Internal Error").code(500);
            }
        }
    });

    // 5. Prototype Pollution / Recursive Merge
    server.route({
        method: 'POST',
        path: '/api/config/update',
        handler: (request, h) => {
            const defaultPrefs = { theme: "light", language: "es" };
            const userPrefs = request.payload;

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
                return "Great!: Privileges OK";
            }

            return "Update Configs";
        }
    });

    // 6. Insecure Deserialization (RCE)
    server.route({
        method: 'POST',
        path: '/api/profile/load',
        handler: (request, h) => {
            const encodedData = request.payload.profileData;

            try {
                // Payload: {"rce":"_$$ND_FUNC$$_function(){require('child_process').execSync('touch /tmp/pwned');}()"}
                const profile = serialize.unserialize(encodedData);
                return `Load Profile: ${profile.username}`;
            } catch (err) {
                return h.response("Error Profile").code(500);
            }
        }
    });

    // 7. ReDoS (Regular Expression Denial of Service)
    server.route({
        method: 'POST',
        path: '/api/validate-format',
        handler: (request, h) => {
            const { input } = request.payload;

            if (!input) return h.response("Non Input").code(400);

            try {
                // Payload: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa!"
                const isValid = emailRegex.test(input);
                return `Invalid format: ${isValid}`;
            } catch (err) {
                return h.response("Validation Error").code(500);
            }
        }
    });

    // 8. JWT "alg: none" Bypass
    server.route({
        method: 'POST',
        path: '/api/admin/data',
        handler: (request, h) => {
            const token = request.headers.authorization?.split(' ')[1];

            if (!token) return h.response("Invalid Token").code(401);

            try {
                const decodedToken = jwt.decode(token, { complete: true });
                if (!decodedToken) throw new Error();
                
                const decodedHeader = decodedToken.header;
                const algorithmToUse = decodedHeader.alg === 'none' ? 'none' : 'HS256';

                // Bypass de firma permitiendo "none"
                if (algorithmToUse === 'none') {
                    const payload = jwt.decode(token); 
                    if (payload.role === 'admin') {
                        return "Secret Admin Data: [VULNERABLE]";
                    }
                }

                const user = jwt.verify(token, SECRET_KEY);
                return `Hello ${user.username}, you are normal user.`;

            } catch (err) {
                return h.response("Invalid Token").code(403);
            }
        }
    });

    // 9. Mass Assignment (Asignación Masiva)
    server.route({
        method: 'PUT',
        // Nota: En Hapi los parámetros de ruta se definen con llaves {} en lugar de :
        path: '/api/users/{id}', 
        handler: (request, h) => {
            const userId = request.params.id;
            const updateData = request.payload; 

            if (!usersDB[userId]) {
                return h.response("Invalid User").code(404);
            }

            // Payload: {"email": "hacker@jl4b.net", "isAdmin": true}
            usersDB[userId] = { ...usersDB[userId], ...updateData };

            return {
                message: "Update Profile: Success",
                user: usersDB[userId]
            };
        }
    });

    // 10. SSRF en importación de Avatar
    server.route({
        method: 'POST',
        path: '/api/profile/avatar/import',
        handler: async (request, h) => {
            const { avatarUrl } = request.payload;

            if (!avatarUrl) return h.response("Avatar Image URL").code(400);

            try {
                // Payload: "http://169.254.169.254/latest/meta-data/"
                const response = await axios.get(avatarUrl);
                
                return {
                    message: "Downloaded Avatar",
                    dataPreview: response.data.substring(0, 200) 
                };
            } catch (err) {
                return h.response("Error On Download Avatar").code(500);
            }
        }
    });

    // 11. HMAC Signature Bypass (Timing/Type confusion)
    server.route({
        method: 'POST',
        path: '/api/webhooks/payment',
        handler: (request, h) => {
            const payload = JSON.stringify(request.payload);
            const signatureProvided = request.headers['x-signature']; 

            const expectedSignature = crypto
                .createHmac('sha256', WEBHOOK_SECRET)
                .update(payload)
                .digest('hex');

            // Vulnerabilidad en la comparación directa (Timing attack)
            if (signatureProvided === expectedSignature) {
                return "Pay OK";
            } else {
                return h.response("Error: Invalid Sign").code(403);
            }
        }
    });

    // 12. HTTP Parameter Pollution (HPP) / Type Confusion
    server.route({
        method: 'GET',
        path: '/api/transfer',
        handler: (request, h) => {
            const account = request.query.account;

            if (!account) return h.response("Invalid Account").code(400);

            // Payload: "/?account=0000&account=1234"
            // Al igual que Express, Hapi convierte múltiples query parameters del mismo nombre en un Array
            if (account === "0000") {
                return h.response("Invalid Transfer").code(403);
            }

            processTransferToDB(account); 

            return `Transfer Start To: ${account}`;
        }
    });

    function processTransferToDB(acc) {
        const targetAccount = Array.isArray(acc) ? acc[0] : acc;
        console.log(`[ERROR] Transfer to account: ${targetAccount}`);
    }

    // --- Arrancar el Servidor ---
    await server.start();
    console.log('Servidor Hapi.js vulnerable escuchando en %s', server.info.uri);
};

process.on('unhandledRejection', (err) => {
    console.log(err);
    process.exit(1);
});

init();
