/*
  Fastify: Vulnerable to Parameter Pollution ( ManticoreSearch )


*/

const fastify = require('fastify')();

const queryManticore = async (term) => {
    return { 
        status: "success", 
        executed_query: `SELECT * FROM idx_test WHERE MATCH('${term}')` 
    };
};

fastify.get('/api/search', async (request, reply) => {
    const { term } = request.query;

    // Vulnerability: Logic assumes 'term' is always a string
    if (term.length > 20) {
        return reply.status(400).send({ error: "Query too long" });
    }

    const results = await queryManticore(term);
    return results;
});

fastify.listen({ port: 3000 });
