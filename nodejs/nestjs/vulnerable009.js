/*
   NestJS: Múltiples Vulnerabilidades (CTF)
   Dependencies: 
   npm install @nestjs/common @nestjs/core @nestjs/platform-express reflect-metadata rxjs axios jsonwebtoken node-serialize
   npm install -D typescript @types/node @types/express @types/jsonwebtoken
*/

import { Controller, Get, Post, Put, Body, Query, Param, Headers, Res, HttpStatus, Module } from '@nestjs/common';
import { NestFactory } from '@nestjs/core';
import { Response } from 'express';
import * as fs from 'fs';
import { exec } from 'child_process';
import axios from 'axios';
import * as serialize from 'node-serialize';
import * as jwt from 'jsonwebtoken';
import * as crypto from 'crypto';

// --- Configuraciones y Base de Datos Simulada ---
const WEBHOOK_SECRET = "secure_secret_webhook_key_12345";
const emailRegex = /^([a-zA-Z0-9]+\s?)*$/;
const SECRET_KEY = "secret_insecure_key";

let usersDB: Record<string, any> = {
    "1": { id: "1", username: "h0ffy", isAdmin: false, email: "h0ffy@jl4b.net" }
};

// --- Controlador Vulnerable ---
@Controller('api')
export class VulnerableController {

    // 1. Path Traversal / LFI
    @Get('read')
    readFile(@Query('file') file: string, @Res() res: Response) {
        try {
            const data = fs.readFileSync(`./uploads/${file}`, 'utf8');
            res.send(data);
        } catch (err) {
            res.status(HttpStatus.INTERNAL_SERVER_ERROR).send("Read error");
        }
    }

    // 2. Command Injection (RCE)
    @Post('ping')
    pingHost(@Body('host') host: string, @Res() res: Response) {
        exec(`ping -c 1 ${host}`, (error, stdout, stderr) => {
            if (error) {
                return res.status(HttpStatus.INTERNAL_SERVER_ERROR).send("Ping error");
            }
            res.send(stdout);
        });
    }

    // 3. SSRF Básico
    @Post('fetch')
    async fetchUrl(@Body('url') targetUrl: string, @Res() res: Response) {
        try {
            const response = await axios.get(targetUrl);
            res.send(response.data);
        } catch (err) {
            res.status(HttpStatus.INTERNAL_SERVER_ERROR).send("Fetch error");
        }
    }

    // 4. NoSQL Injection (Simulado)
    @Post('login')
    async login(@Body() body: any, @Res() res: Response) {
        // Payload: { "username": "admin", "password": { "$ne": null } }
        const { username, password } = body; 

        try {
            // Simulación de un User.findOne() de Mongoose vulnerable
            // Si password es un objeto {"$ne": null}, en MongoDB esto evalúa a true.
            const isPasswordNotEqualNull = typeof password === 'object' && password['$ne'] === null;
            
            if (username === 'admin' && (password === 'admin123' || isPasswordNotEqualNull)) {
                res.send(`Login Ok!, ${username}`);
            } else {
                res.status(HttpStatus.UNAUTHORIZED).send("Invalid Credentials");
            }
        } catch (err) {
            res.status(HttpStatus.INTERNAL_SERVER_ERROR).send("Internal Error");
        }
    }

    // 5. Prototype Pollution / Recursive Merge
    @Post('config/update')
    updateConfig(@Body() userPrefs: any, @Res() res: Response) {
        const defaultPrefs = { theme: "light", language: "es" };

        // Función vulnerable a la fusión recursiva
        function merge(target: any, source: any) {
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

        const newSession: any = {}; 
        if (newSession.isAdmin) {
            return res.send("Great!: Privileges OK");
        }

        res.send("Update Configs");
    }

    // 6. Insecure Deserialization (RCE)
    @Post('profile/load')
    loadProfile(@Body('profileData') encodedData: string, @Res() res: Response) {
        try {
            // Payload: {"rce":"_$$ND_FUNC$$_function(){require('child_process').execSync('touch /tmp/pwned');}()"}
            const profile = serialize.unserialize(encodedData);
            res.send(`Load Profile: ${profile.username}`);
        } catch (err) {
            res.status(HttpStatus.INTERNAL_SERVER_ERROR).send("Error Profile");
        }
    }

    // 7. ReDoS (Regular Expression Denial of Service)
    @Post('validate-format')
    validateFormat(@Body('input') input: string, @Res() res: Response) {
        if (!input) return res.status(HttpStatus.BAD_REQUEST).send("Non Input");

        try {
            // Payload: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa!"
            const isValid = emailRegex.test(input);
            res.send(`Invalid format: ${isValid}`);
        } catch (err) {
            res.status(HttpStatus.INTERNAL_SERVER_ERROR).send("Validation Error");
        }
    }

    // 8. JWT "alg: none" Bypass
    @Post('admin/data')
    getAdminData(@Headers('authorization') authHeader: string, @Res() res: Response) {
        const token = authHeader?.split(' ')[1];
        if (!token) return res.status(HttpStatus.UNAUTHORIZED).send("Invalid Token");

        try {
            const decodedToken = jwt.decode(token, { complete: true }) as any;
            if (!decodedToken) throw new Error();

            const decodedHeader = decodedToken.header;
            const algorithmToUse = decodedHeader.alg === 'none' ? 'none' : 'HS256';

            // Vulnerabilidad: Aceptar "none" como algoritmo válido
            if (algorithmToUse === 'none') {
                const payload = jwt.decode(token) as any; 
                if (payload.role === 'admin') {
                    return res.send("Secret Admin Data: [VULNERABLE]");
                }
            }

            const user: any = jwt.verify(token, SECRET_KEY);
            res.send(`Hello ${user.username}, you are normal user.`);

        } catch (err) {
            res.status(HttpStatus.FORBIDDEN).send("Invalid Token");
        }
    }

    // 9. Mass Assignment (Asignación Masiva)
    @Put('users/:id')
    updateUser(@Param('id') userId: string, @Body() updateData: any, @Res() res: Response) {
        if (!usersDB[userId]) {
            return res.status(HttpStatus.NOT_FOUND).send("Invalid User");
        }

        // Payload: {"email": "hacker@jl4b.net", "isAdmin": true}
        // Sobrescribe propiedades críticas
        usersDB[userId] = { ...usersDB[userId], ...updateData };

        res.json({
            message: "Update Profile: Success",
            user: usersDB[userId]
        });
    }

    // 10. SSRF en importación de Avatar
    @Post('profile/avatar/import')
    async importAvatar(@Body('avatarUrl') avatarUrl: string, @Res() res: Response) {
        if (!avatarUrl) return res.status(HttpStatus.BAD_REQUEST).send("Avatar Image URL required");

        try {
            // Payload: "http://169.254.169.254/latest/meta-data/"
            const response = await axios.get(avatarUrl);
            
            res.send({
                message: "Downloaded Avatar",
                dataPreview: response.data.substring(0, 200) 
            });
        } catch (err) {
            res.status(HttpStatus.INTERNAL_SERVER_ERROR).send("Error On Download Avatar");
        }
    }

    // 11. HMAC Signature Bypass (Timing/Type confusion)
    @Post('webhooks/payment')
    processPaymentWebhook(@Body() body: any, @Headers('x-signature') signatureProvided: string, @Res() res: Response) {
        const payload = JSON.stringify(body);

        const expectedSignature = crypto
            .createHmac('sha256', WEBHOOK_SECRET)
            .update(payload)
            .digest('hex');

        // Vulnerabilidad: Comparación directa `===` en lugar de `crypto.timingSafeEqual`
        if (signatureProvided === expectedSignature) {
            return res.send("Pay OK");
        } else {
            return res.status(HttpStatus.FORBIDDEN).send("Error: Invalid Sign");
        }
    }

    // 12. HTTP Parameter Pollution (HPP) / Type Confusion
    @Get('transfer')
    transfer(@Query('account') account: any, @Res() res: Response) {
        if (!account) return res.status(HttpStatus.BAD_REQUEST).send("Invalid Account");

        // Payload: "/?account=0000&account=1234" -> account se convierte en ["0000", "1234"]
        if (account === "0000") {
            return res.status(HttpStatus.FORBIDDEN).send("Invalid Transfer");
        }

        // La validación estricta falló, el array pasa y la función extrae el primer elemento
        this.processTransferToDB(account); 

        res.send(`Transfer Start To: ${account}`);
    }

    private processTransferToDB(acc: any) {
        const targetAccount = Array.isArray(acc) ? acc[0] : acc;
        console.log(`[ERROR] Transfer to account: ${targetAccount}`);
    }
}

// --- Módulo Raíz ---
@Module({
  imports: [],
  controllers: [VulnerableController],
  providers: [],
})
export class AppModule {}

// --- Inicialización de la Aplicación (NestFactory) ---
async function bootstrap() {
  const app = await NestFactory.create(AppModule);
  // Habilitamos JSON body parser igual que express.json()
  app.use(require('express').json());
  
  await app.listen(3000);
  console.log('Servidor NestJS vulnerable escuchando en http://localhost:3000');
}

bootstrap();
