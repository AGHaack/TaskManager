const express = require('express');
const { ApolloServer } = require('apollo-server-express');
const cors = require('cors');
const dotEnv = require('dotenv');

const resolvers = require('./resolvers');
const typeDefs = require('./typeDefs/index');
const { connection } = require('./database/util');

dotEnv.config();

const app = express();

// db connectivity
connection();

// cors
app.use(cors());

// body parser middleware
app.use(express.json());

const apolloServer = new ApolloServer({
    typeDefs,
    resolvers
});

apolloServer.applyMiddleware({app, path: '/graphql'})

const PORT = process.env.PORT || 4000;

app.use('/', (req, res, next) => {
    res.send({message: 'Hello'});
});

app.listen(PORT, () => {
    console.log(`Server listening on PORT: ${PORT}`);
    console.log(`Graphql Endpoint: ${apolloServer.graphqlPath}`);
});