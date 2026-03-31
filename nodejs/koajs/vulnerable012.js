/*
   Koa.js: Multiple Vulnerabilities (CTF)
   Depdends:
   npm install koa koa-router koa-bodyparser axios jsonwebtoken node-serialize
*/

const Koa = require('koa');
const Router = require('koa-router');
const bodyParser = require('koa-bodyparser');
const fs = require('fs');
const util = require('util');
const { exec } = require('child_process');
const execPromise = util.promisify(exec); // Koa maneja mejor promesas que callbacks
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

const app = new Koa();
const router = new Router();

// Middleware para parsear el body en JSON
app.use(bodyParser());

// 1. Path Traversal / LFI
router.get('/api/read', async (ctx) => {
    const file = ctx.query.file; // En Koa se usa ctx.query
    try {
        const data = fs.readFileSync(`./uploads/${file}`, 'utf8');
        ctx.body = data;
    } catch (err) {
        ctx.status = 500;
        ctx.body = "Read error";
    }
});

// 2. Command Injection (RCE)
router.post('/api/ping', async (ctx) => {
    const host = ctx.request.body.host; // En Koa el body está en ctx.request.body
    
    try {
        // VULNERABLE: El payload viaja directo a la terminal
        const { stdout } = await execPromise(`ping -c 1 ${host}`);
        ctx.body = stdout;
    } catch (error) {
        ctx.status = 500;
        ctx.body = "Ping error";
    }
});

// 3. SSRF Básico
router.post('/api/fetch', async (ctx) => {
    const targetUrl = ctx.request.body.url;
    try {
        const response = await axios.get(targetUrl);
        ctx.body = response.data;
    } catch (err) {
        ctx.status = 500;
        ctx.body = "Fetch error";
    }
});

// 4. NoSQL Injection (Simulado)
router.post('/api/login', async (ctx) => {
    // Payload: { "username": "admin", "password": { "$ne": null } }
    const { username, password } = ctx.request.body; 

    try {
        const isPasswordNotEqualNull = typeof password === 'object' && password['$ne'] === null;
        
        if (username === 'admin' && (password === 'admin123' || isPasswordNotEqualNull)) {
            ctx.body = `Login Ok!, ${username}`;
        } else {
            ctx.status = 401;
            ctx.body = "Invalid Credentials";
        }
    } catch (err) {
        ctx.status = 500;
        ctx.body = "Internal Error";
    }
});

// 5. Prototype Pollution / Recursive Merge
router.post('/api/config/update', async (ctx) => {
    const defaultPrefs = { theme: "light", language: "es" };
    const userPrefs = ctx.request.body;

    // Función vulnerable a la fusión recursiva
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
        ctx.body = "Great!: Privileges OK";
        return;
    }

    ctx.body = "Update Configs";
});

// 6. Insecure Deserialization (RCE)
router.post('/api/profile/load', async (ctx) => {
    const encodedData = ctx.request.body.profileData;

    try {
        // Payload: {"rce":"_$$ND_FUNC$$_function(){require('child_process').execSync('touch /tmp/pwned');}()"}
        const profile = serialize.unserialize(encodedData);
        ctx.body = `Load Profile: ${profile.username}`;
    } catch (err) {
        ctx.status = 500;
        ctx.body = "Error Profile";
    }
});

// 7. ReDoS (Regular Expression Denial of Service)
router.post('/api/validate-format', async (ctx) => {
    const { input } = ctx.request.body;

    if (!input) {
        ctx.status = 400;
        ctx.body = "Non Input";
        return;
    }

    try {
        // Payload: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa!"
        const isValid = emailRegex.test(input);
        ctx.body = `Invalid format: ${isValid}`;
    } catch (err) {
        ctx.status = 500;
        ctx.body = "Validation Error";
    }
});

// 8. JWT "alg: none" Bypass
router.post('/api/admin/data', async (ctx) => {
    const token = ctx.headers.authorization?.split(' ')[1];

    if (!token) {
        ctx.status = 401;
        ctx.body = "Invalid Token";
        return;
    }

    try {
        const decodedToken = jwt.decode(token, { complete: true });
        if (!decodedToken) throw new Error();

        const decodedHeader = decodedToken.header;
        const algorithmToUse = decodedHeader.alg === 'none' ? 'none' : 'HS256';

        if (algorithmToUse === 'none') {
            const payload = jwt.decode(token); 
            if (payload.role === 'admin') {
                ctx.body = "Secret Admin Data: [VULNERABLE]";
                return;
            }
        }

        const user = jwt.verify(token, SECRET_KEY);
        ctx.body = `Hello ${user.username}, you are normal user.`;

    } catch (err) {
        ctx.status = 403;
        ctx.body = "Invalid Token";
    }
});

// 9. Mass Assignment (Asignación Masiva)
router.put('/api/users/:id', async (ctx) => {
    const userId = ctx.params.id; // En Koa-router los params están en ctx.params
    const updateData = ctx.request.body; 

    if (!usersDB[userId]) {
        ctx.status = 404;
        ctx.body = "Invalid User";
        return;
    }

    // Payload: {"email": "h0ffy@jl4b.net", "isAdmin": true}
    usersDB[userId] = { ...usersDB[userId], ...updateData };

    ctx.body = {
        message: "Update Profile: Success",
        user: usersDB[userId]
    };
});

// 10. SSRF en importación de Avatar
router.post('/api/profile/avatar/import', async (ctx) => {
    const { avatarUrl } = ctx.request.body;

    if (!avatarUrl) {
        ctx.status = 400;
        ctx.body = "Avatar Image URL";
        return;
    }

    try {
        // Payload: "http://169.254.169.254/latest/meta-data/"
        const response = await axios.get(avatarUrl);
        
        ctx.body = {
            message: "Downloaded Avatar",
            dataPreview: response.data.substring(0, 200) 
        };
    } catch (err) {
        ctx.status = 500;
        ctx.body = "Error On Download Avatar";
    }
});

// 11. HMAC Signature Bypass (Timing/Type confusion)
router.post('/api/webhooks/payment', async (ctx) => {
    const payload = JSON.stringify(ctx.request.body);
    const signatureProvided = ctx.headers['x-signature']; 

    const expectedSignature = crypto
        .createHmac('sha256', WEBHOOK_SECRET)
        .update(payload)
        .digest('hex');

    if (signatureProvided === expectedSignature) {
        ctx.body = "Pay OK";
    } else {
        ctx.status = 403;
        ctx.body = "Error: Invalid Sign";
    }
});

// 12. HTTP Parameter Pollution (HPP) / Type Confusion
router.get('/api/transfer', async (ctx) => {
    const account = ctx.query.account;

    if (!account) {
        ctx.status = 400;
        ctx.body = "Invalid Account";
        return;
    }

    // Payload: "/?account=0000&account=1234"
    // ctx.query.account de Koa, al igual que Express, agrupa múltiples parámetros idénticos en un Array
    if (account === "0000") {
        ctx.status = 403;
        ctx.body = "Invalid Transfer";
        return;
    }

    processTransferToDB(account); 

    ctx.body = `Transfer Start To: ${account}`;
});

function processTransferToDB(acc) {
    const targetAccount = Array.isArray(acc) ? acc[0] : acc;
    console.log(`[ERROR] Transfer to account: ${targetAccount}`);
}

// Inicializar router y servidor
app.use(router.routes()).use(router.allowedMethods());

app.listen(3000, () => {
    console.log('Servidor Koa.js vulnerable escuchando en http://localhost:3000');
});
