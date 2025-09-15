import express from 'express';
import { PORT } from './config.js';
import { UserRepository } from './repository/user-repository.js';

const app = express();
app.set('view engine', 'ejs');
app.use(express.json()); // Use middleware to transform req.body to JSON

app.get('/', (req, res) => {
	res.render('./base', { name: 'alex' });
});

// User session control
app.post('/login', async (req, res) => {
	try {
		const { username, password } = req.body;
		const user = await UserRepository.login({ username, password });
		res.send(user);
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
app.post('/protected', (req, res) => {});

app.listen(PORT, () => {
	console.log(`Server running on port ${PORT}...`);
});
