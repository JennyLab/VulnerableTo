/*
    Fastify: Vulnerable to Parameter Pollution (GraphQL)

*/

const fastify = require('fastify')();
const mercurius = require('mercurius');

const schema = `
  type User {
    id: ID!
    username: String!
    role: String!
  }

  type Query {
    user(id: ID!): User
    search(term: String!): [User]
  }
`;

const users = {
  1: { id: 1, username: 'admin', role: 'superuser' },
  2: { id: 2, username: 'guest', role: 'viewer' }
};

const resolvers = {
  Query: {
    user: async (_, { id }) => users[id],
    search: async (_, { term }) => {
      // Logic flaw: term could be an array due to HPP if not validated
      return Object.values(users).filter(u => u.username.includes(term));
    }
  }
};

fastify.register(mercurius, {
  schema,
  resolvers,
  graphiql: true, // Vulnerability: UI enabled in production
  introspection: true // Vulnerability: Schema discovery enabled
});

fastify.listen({ port: 3000 });
