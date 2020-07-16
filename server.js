
const express = require('express');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcrypt');
const fs = require('fs');

const app = express();

function authorize(...allowed) {
    const isAllowed = role => allowed.indexOf(role) > -1;

    return (req, res, next) => {

        var token = req.headers['token'];
        if (!token) {
            res.status(401).json({message: "Denied Access"});
        }

        const publicKey = fs.readFileSync('./public.key', 'utf-8');

        jwt.verify(token, publicKey, { algorithms: ['RS256'] }, function(err, decoded) {
            if (err) {
                res.status(401).json({message: "Invalid token"});
            }

            if(isAllowed(decoded.role)) {
                next()
            } else {
                res.status(403).json({ message: "Denied" });
            }
        })
    }
}

app.use(express.json());
app.use(express.urlencoded({ extended: true }));

var users = {}; // Mock database
app.post('/createUser', (req, res) => {

    const encryptedPwd = bcrypt.hashSync(req.body.password, 1);

    users[req.body.username] = {
        encryptedPwd: encryptedPwd,
        role: req.body.role
    }

    res.status(201).json({ message: `User ${req.body.username} created.`});
})

app.post('/login', (req, res) => {
    if(req.body.username && req.body.password) {

        if(users[req.body.username]) {

            const pwdMatches = bcrypt.compareSync(req.body.password, users[req.body.username].encryptedPwd);

            var privateKey = fs.readFileSync('./private.key', 'utf-8');

            if (pwdMatches) {
                var token = jwt.sign(
                    { role: users[req.body.username].role },
                    privateKey, {
                        expiresIn: 300,
                        algorithm: 'RS256'
                    });

                res.json({ auth: true, token: token });
            } else {
                res.status(401).json({ message: 'Incorrect password'});
            }
        } else {
            res.status(401).json({ message: 'Invalid user'});
        }
    } else {
        res.status(401).json({ message: 'Empty user'});
    }
})

app.use(['/findAll', '/findWhatever'], authorize('admin', 'commonUser'))
app.use('/findSomething', authorize('admin'))

app.get('/findSomething', (req, res) => {
    res.send('findSomething')
})

app.get('/findAll', (req, res) => {
    res.send('findAll')
})

app.get('/findWhatever', (req, res) => {
    res.send('findWhatever')
})

app.listen(3000, () => console.log('Server started'));
