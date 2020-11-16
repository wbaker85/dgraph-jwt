const express = require('express');
const morgan = require('morgan');

const jwt = require('express-jwt');
const jwksRsa = require('jwks-rsa');

const { MongoClient } = require('mongodb');

const url = 'mongodb://mongo:27017';
const dbName = 'jwks';
const collectionName = 'uris';

const establishCollection = async () => {
  const client = await MongoClient.connect(url);
  const db = client.db(dbName);
  const collection = db.collection(collectionName);
  return collection;
};

const port = 4000;

const verifySpecificJWT = async (req, res, next) => {
  const subdomain = req.subdomains[0];
  const collection = await establishCollection();
  const uriObj = await collection.find({ _id: subdomain }).toArray();

  if (uriObj.length === 0) {
    res.sendStatus(401);
  } else {
    const uri = uriObj[0].uri;

    const checkJwt = jwt({
      secret: jwksRsa.expressJwtSecret({
        cache: true,
        rateLimit: true,
        jwksRequestsPerMinute: 5,
        jwksUri: uri,
      }),
      algorithms: ['RS256'],
    });

    checkJwt(req, res, next);
  }
};

const app = express();
app.use(morgan('combined'));

app.get('/', (req, res) => {
  res.send('Hello from admin server!');
});

app.post('/oauth/token', verifySpecificJWT, (req, res) => {
  const authString = req.headers.authorization;
  const token = authString.split(' ')[1];

  res.set('X-Dgraph-AccessToken', token);
  res.status(200).send();
});

app.use(function (err, req, res, next) {
  res.status(401).json({
    data: {
      Message: 'Invalid credentials',
    },
  });
});

app.listen(port, () => {
  console.log(`Server ready`);
});
