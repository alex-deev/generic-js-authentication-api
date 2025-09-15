import crypto from 'node:crypto';
import bcrypt from 'bcrypt';
import dbLocal from 'db-local';
import { SALT_ROUNDS } from '../config.js';

// Creates database file in src/db
const { Schema } = new dbLocal({ path: './src/db/' });

// Creates User schema in db
const User = Schema('User', {
	_id: { type: String, required: true },
	username: { type: String, required: true },
	password: { type: String, required: true },
});

// biome-ignore lint/complexity/noStaticOnlyClass: <explanation>
export class UserRepository {
	static async create({ username, password }) {
		// 1. username & password validation
		Validation.username(username);
		Validation.password(password);

		// 2. ensure username does not exist yet
		const user = User.findOne({ username });
		if (user) throw new Error('username already exists');

		// 3. user creation
		const id = crypto.randomUUID(); // since db-local does not auto-generates one
		const hashedPassword = await bcrypt.hashSync(password, SALT_ROUNDS); // password hashing
		User.create({
			_id: id,
			username,
			password: hashedPassword,
		}).save();

		return id;
	}

	static async login({ username, password }) {
		// 1. username & password validation
		Validation.username(username);
		Validation.password(password);

		// 2. ensure username exists
		const user = User.findOne({ username });
		if (!user) throw new Error('username does not exist');

		// 3. check if received hashed-password is the same as stored
		const isValid = await bcrypt.compare(password, user.password);
		if (!isValid) throw new Error('password is invalid');

		// 4. omit some properties of user
		const { password: _, ...publicUser } = user; // only omits object prop 'password'

		return publicUser;
	}
}

// biome-ignore lint/complexity/noStaticOnlyClass: <explanation>
class Validation {
	// could use external library like zod
	/** username validation */
	static username(username) {
		if (typeof username !== 'string')
			throw new Error('username must be a string');
		if (username.length < 3)
			throw new Error('username must be at least 3 characters long');
	}
	/** password validation */
	static password(password) {
		if (typeof password !== 'string')
			throw new Error('password must be a string');
		if (password.length < 6)
			throw new Error('password must be at least 6 characters long');
	}
}
