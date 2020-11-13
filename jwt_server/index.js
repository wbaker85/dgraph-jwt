const express = require('express');
const morgan = require('morgan');

const jwt = require('express-jwt');
const jwksRsa = require('jwks-rsa');

const port = process.env.PORT;

const checkJwt = jwt({
  secret: jwksRsa.expressJwtSecret({
    cache: true,
    rateLimit: true,
    jwksRequestsPerMinute: 5,
    jwksUri: process.env.JWKS_URI,
  }),
  algorithms: ['RS256'],
});

const app = express();
app.use(morgan('combined'));

app.post('/oauth/token', checkJwt, (req, res) => {
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
  console.log(
    `Server ready at https://${process.env.HOST_NAME}:${process.env.PORT}`
  );
});
