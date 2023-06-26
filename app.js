const fs = require('fs');
const bodyParser = require('body-parser');
const jsonServer = require('json-server');
const jwt = require('jsonwebtoken');

const SECRET_KEY = '123456789';
const expiresIn = '1h';

const db = JSON.parse(fs.readFileSync('./db.json', 'UTF-8'));

function createToken (payload) {
    return jwt.sign(payload, SECRET_KEY, { expiresIn });
}

function verifyToken (token) {
    return jwt.verify(token, SECRET_KEY, (err, decode) => decode !== undefined ? decode : err);
}

function isAuthenticated ({ email, password }) {
    return db.users.findIndex(user => user.email === email && user.password === password) !== -1;
}

function getUserFromCredentials ({ email, password }) {
    return db.users.find(user => user.email === email && user.password === password);
}

const server = jsonServer.create();
const router = jsonServer.router('./db.json');

server.use(jsonServer.defaults());
server.use(bodyParser.urlencoded({ extended: true }))
server.use(bodyParser.json());

server.post('/auth/login', (req, res) => {
    const { email, password } = req.body;
    if (isAuthenticated({ email, password }) === false) {
        const status = 401;
        const message = 'Authentification incorrecte'
        res.status(status).json({ status, message });
        return
    }
    const access_token = createToken({ email, password });
    const user = getUserFromCredentials({ email, password });
    res.status(200).json({ token: access_token, user: user });
});

server.post('/auth/register', (req, res) => {
    const { email, username, role, password } = req.body;
    const user = { email, password, username, role };
    user.id = new Date().getTime();

    db.users.push(user);

    fs.writeFileSync('./db.json', JSON.stringify(db));

    const access_token = createToken({ email, password });
    res.status(200).json({ token: access_token, user });
});

server.use(/^(?!\/(auth|public)).*$/, (req, res, next) => {
    if (req.headers.authorization === undefined || req.headers.authorization.split(' ')[0] !== 'Bearer') {
        const status = 401;
        const message = 'Mauvais en-tête d\'authentification'
        res.status(status).json({ status, message })
        return
    }
    try {
        verifyToken(req.headers.authorization.split(' ')[1])
        next()
    } catch (err) {
        const status = 401
        const message = 'Token non valide'
        res.status(status).json({ status, message })
    }
});

server.use(router);

server.listen(3000, () => {
    console.log('Run Auth API Server');
});

