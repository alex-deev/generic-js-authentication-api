import cookieParser from 'cookie-parser';
import express from 'express';
import jwt from 'jsonwebtoken';
import { JWT_SECRET_KEY, PORT } from './config.js';
import { UserRepository } from './repository/user-repository.js';

const app = express();

app.set('view engine', 'ejs');
app.use(express.json()); // Middleware to transform req.body to JSON
app.use(cookieParser()); // Middleware to attach/modify Cookies on requests

app.use((req, res, next) => {
	const timestamp = new Date().toISOString();
	console.log(`${timestamp} - ${req.method} ${req.originalUrl} from ${req.ip}`);
	next(); // Call next to pass control to the next middleware/route handler
});

app.get('/', (req, res) => {
	res.render('./index');
});

// User session control
app.post('/login', async (req, res) => {
	const { username, password } = req.body;
	try {
		// 1. retrieves user data from DB
		const user = await UserRepository.login({ username, password });

		// 2. creates Json Web Token Signature
		const token = await jwt.sign(
			{
				// payload
				id: user._id,
				username: username,
			},
			JWT_SECRET_KEY, // signature key
			{
				// header meta
				expiresIn: '1h',
			},
		);

		// 3. responds with cookie and data
		res
			.cookie('access_token', token, {
				httpOnly: true, // only server management of cookie
				sameSite: 'strict', // cookie only available on same domain
				maxAge: 1000 * 60 * 60, // cookie expires after 1 hour
				// secure: true, // DISABLED cookie only accessible via HTTPs
			})
			.send(user);
	} catch (error) {
		res.status(401).send(error.message);
	}
});
app.post('/register', async (req, res) => {
	try {
		const { username, password } = req.body;
		const id = await UserRepository.create({ username, password });
		res.status(200).send(`User ${username} created with id: ${id}!`);
	} catch (error) {
		res.status(400).send(error.message);
	}
});
app.post('/logout', (req, res) => {});

// Protected route
app.get('/protected', (req, res) => {
	// 1. checks if token is present (means user previously authenticated)
	const token = req.cookies.access_token;
	if (!token) {
		return res.status(403).send('Cannot access here. Protected route 🔒.');
	}

	try {
		// 2. checks if token is valid for this site (has the same header, payload and signature key)
		const data = jwt.verify(token, JWT_SECRET_KEY);

		// 3. authorizes the request and provide the route source
		res.render('./protected', data);
	} catch (error) {
		return res
			.status(401)
			.send('Access not authorized. Authentication is not valid.');
	}
});

const server = app.listen(PORT, () => {
	console.log(`Server running on port ${PORT}...`);
});

// Custom error handlers
server.on('error', (e) => {
	if (e.code === 'EADDRINUSE') {
		console.log(`Port ${PORT} is already in use.`);
		console.log(`Shutting down.`);
	}
	console.error('Server error:', e);
});
