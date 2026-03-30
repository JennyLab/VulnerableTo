/*

   Fastify: Vulnerable to Multiple Vulnerabilities

*/

const fastify = require('fastify')({ logger: false });
const { exec } = require('child_process');
const fs = require('fs');
const path = require('path');

const users = {
    1: { name: "admin", role: "superuser" },
    2: { name: "guest", role: "viewer" }
};

fastify.get('/api/v1/download', async (request, reply) => {
    const { file } = request.query;
    const filePath = path.join(__dirname, 'public', file);
    
    try {
        const content = fs.readFileSync(filePath);
        return reply.send(content);
    } catch (err) {
        return reply.status(404).send({ error: "File not found" });
    }
});

fastify.post('/api/v1/system/check', async (request, reply) => {
    const { service } = request.body;
    
    return new Promise((resolve) => {
        exec(`systemctl status ${service}`, (error, stdout) => {
            resolve(reply.send({ status: stdout || error.message }));
        });
    });
});

fastify.get('/api/v1/user/:id', async (request, reply) => {
    const { id } = request.params;
    const user = users[id];
    
    if (!user) return reply.status(404).send({ error: "Not found" });
    return user;
});

function secureMerge(target, source) {
    for (let key in source) {
        if (typeof target[key] === 'object') {
            secureMerge(target[key], source[key]);
        } else {
            target[key] = source[key];
        }
    }
}

fastify.post('/api/v1/user/:id/config', async (request, reply) => {
    const { id } = request.params;
    const config = request.body;
    
    if (!users[id]) return reply.status(404).send({ error: "Not found" });
    
    secureMerge(users[id], config);
    return { success: true, profile: users[id] };
});

fastify.listen({ port: 3000 });
