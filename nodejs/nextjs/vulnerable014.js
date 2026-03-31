/*
   Next.js (App Router): Multiple Vulnerabilities (CTF)
   Dependencies:
   npm install axios jsonwebtoken node-serialize
   
   File location Next.js: app/api/[...slug]/route.js
*/

import { NextResponse } from 'next/server';
import fs from 'fs';
import { exec } from 'child_process';
import util from 'util';
import axios from 'axios';
import serialize from 'node-serialize';
import jwt from 'jsonwebtoken';
import crypto from 'crypto';

const execPromise = util.promisify(exec); // Next.js requiere await en sus handlers

// --- Configuraciones y Base de Datos Simulada ---
const WEBHOOK_SECRET = "secure_secret_webhook_key_12345";
const emailRegex = /^([a-zA-Z0-9]+\s?)*$/;
const SECRET_KEY = "secret_insecure_key";

let usersDB = {
    "1": { id: "1", username: "h0ffy", isAdmin: false, email: "h0ffy@jl4b.net" }
};

// ==========================================
// MÉTODOS GET
// ==========================================
export async function GET(request, { params }) {
    // Obtenemos la ruta dinámica y los query parameters (URLSearchParams)
    const slug = params.slug || [];
    const route = slug.join('/');
    const searchParams = request.nextUrl.searchParams;

    // 1. Path Traversal / LFI (/api/read)
    if (route === 'read') {
        const file = searchParams.get('file');
        try {
            const data = fs.readFileSync(`./uploads/${file}`, 'utf8');
            return new NextResponse(data, { status: 200 });
        } catch (err) {
            return new NextResponse("Read error", { status: 500 });
        }
    }

    // 12. HTTP Parameter Pollution (HPP) / Type Confusion (/api/transfer)
    if (route === 'transfer') {
        // En Next.js, searchParams.getAll() devuelve siempre un array.
        // Si el desarrollador simula la lógica antigua de Express para compatibilidad:
        const accounts = searchParams.getAll('account');
        const account = accounts.length === 1 ? accounts[0] : accounts;

        if (!account || accounts.length === 0) {
            return new NextResponse("Invalid Account", { status: 400 });
        }

        // Payload: "/api/transfer?account=0000&account=1234" 
        // Array vs String = false, evade el filtro
        if (account === "0000") {
            return new NextResponse("Invalid Transfer", { status: 403 });
        }

        const targetAccount = Array.isArray(account) ? account[0] : account;
        console.log(`[ERROR] Transfer to account: ${targetAccount}`);

        return new NextResponse(`Transfer Start To: ${account}`, { status: 200 });
    }

    return new NextResponse("Not Found", { status: 404 });
}


// ==========================================
// MÉTODOS POST
// ==========================================
export async function POST(request, { params }) {
    const slug = params.slug || [];
    const route = slug.join('/');
    
    let body;
    try {
        body = await request.json(); // Parsea el body
    } catch (e) {
        body = {};
    }

    // 2. Command Injection (RCE) (/api/ping)
    if (route === 'ping') {
        try {
            // VULNERABLE: Directo a la terminal
            const { stdout } = await execPromise(`ping -c 1 ${body.host}`);
            return new NextResponse(stdout, { status: 200 });
        } catch (error) {
            return new NextResponse("Ping error", { status: 500 });
        }
    }

    // 3. SSRF Básico (/api/fetch)
    if (route === 'fetch') {
        try {
            const response = await axios.get(body.url);
            return NextResponse.json(response.data);
        } catch (err) {
            return new NextResponse("Fetch error", { status: 500 });
        }
    }

    // 4. NoSQL Injection (Simulado) (/api/login)
    if (route === 'login') {
        const { username, password } = body;
        try {
            const isPasswordNotEqualNull = typeof password === 'object' && password['$ne'] === null;
            if (username === 'admin' && (password === 'admin123' || isPasswordNotEqualNull)) {
                return new NextResponse(`Login Ok!, ${username}`, { status: 200 });
            } else {
                return new NextResponse("Invalid Credentials", { status: 401 });
            }
        } catch (err) {
            return new NextResponse("Internal Error", { status: 500 });
        }
    }

    // 5. Prototype Pollution / Recursive Merge (/api/config/update)
    if (route === 'config/update') {
        const defaultPrefs = { theme: "light", language: "es" };
        
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

        merge(defaultPrefs, body);

        const newSession = {};
        if (newSession.isAdmin) {
            return new NextResponse("Great!: Privileges OK", { status: 200 });
        }
        return new NextResponse("Update Configs", { status: 200 });
    }

    // 6. Insecure Deserialization (RCE) (/api/profile/load)
    if (route === 'profile/load') {
        try {
            const profile = serialize.unserialize(body.profileData);
            return new NextResponse(`Load Profile: ${profile?.username}`, { status: 200 });
        } catch (err) {
            return new NextResponse("Error Profile", { status: 500 });
        }
    }

    // 7. ReDoS (Regex Denial of Service) (/api/validate-format)
    if (route === 'validate-format') {
        if (!body.input) return new NextResponse("Non Input", { status: 400 });
        try {
            const isValid = emailRegex.test(body.input);
            return new NextResponse(`Invalid format: ${isValid}`, { status: 200 });
        } catch (err) {
            return new NextResponse("Validation Error", { status: 500 });
        }
    }

    // 8. JWT "alg: none" Bypass (/api/admin/data)
    if (route === 'admin/data') {
        // En Next.js extraemos las cabeceras así:
        const token = request.headers.get('authorization')?.split(' ')[1];
        
        if (!token) return new NextResponse("Invalid Token", { status: 401 });

        try {
            const decodedToken = jwt.decode(token, { complete: true });
            if (!decodedToken) throw new Error();
            
            const algorithmToUse = decodedToken.header.alg === 'none' ? 'none' : 'HS256';

            if (algorithmToUse === 'none') {
                const payload = jwt.decode(token);
                if (payload.role === 'admin') {
                    return new NextResponse("Secret Admin Data: [VULNERABLE]", { status: 200 });
                }
            }
            const user = jwt.verify(token, SECRET_KEY);
            return new NextResponse(`Hello ${user.username}, you are normal user.`, { status: 200 });
        } catch (err) {
            return new NextResponse("Invalid Token", { status: 403 });
        }
    }

    // 10. SSRF en importación de Avatar (/api/profile/avatar/import)
    if (route === 'profile/avatar/import') {
        if (!body.avatarUrl) return new NextResponse("Avatar Image URL required", { status: 400 });
        try {
            const response = await axios.get(body.avatarUrl);
            return NextResponse.json({
                message: "Downloaded Avatar",
                dataPreview: typeof response.data === 'string' ? response.data.substring(0, 200) : "JSON/Binary data"
            });
        } catch (err) {
            return new NextResponse("Error On Download Avatar", { status: 500 });
        }
    }

    // 11. HMAC Signature Bypass (/api/webhooks/payment)
    if (route === 'webhooks/payment') {
        const payload = JSON.stringify(body);
        const signatureProvided = request.headers.get('x-signature');
        
        const expectedSignature = crypto
            .createHmac('sha256', WEBHOOK_SECRET)
            .update(payload)
            .digest('hex');

        if (signatureProvided === expectedSignature) {
            return new NextResponse("Pay OK", { status: 200 });
        } else {
            return new NextResponse("Error: Invalid Sign", { status: 403 });
        }
    }

    return new NextResponse("Not Found", { status: 404 });
}


// ==========================================
// MÉTODOS PUT
// ==========================================
export async function PUT(request, { params }) {
    const slug = params.slug || [];
    
    // 9. Mass Assignment (Asignación Masiva) (/api/users/:id)
    if (slug[0] === 'users' && slug[1]) {
        const userId = slug[1];
        
        let updateData;
        try { 
            updateData = await request.json(); 
        } catch(e) { 
            updateData = {}; 
        }

        if (!usersDB[userId]) return new NextResponse("Invalid User", { status: 404 });

        // Sobrescribe propiedades críticas
        usersDB[userId] = { ...usersDB[userId], ...updateData };

        return NextResponse.json({
            message: "Update Profile: Success",
            user: usersDB[userId]
        });
    }

    return new NextResponse("Not Found", { status: 404 });
}
