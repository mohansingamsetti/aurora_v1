const express = require('express');
const AWS = require('aws-sdk');
const bodyParser = require('body-parser');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const path = require('path');
const dotenv = require('dotenv');

// Load environment variables
dotenv.config();

// Initialize Express app
const app = express();
const PORT = process.env.PORT || 3000;

// Configure AWS
AWS.config.update({
	region: process.env.AWS_REGION || 'us-east-1',
	accessKeyId: process.env.AWS_ACCESS_KEY_ID,
	secretAccessKey: process.env.AWS_SECRET_ACCESS_KEY,
});

// Initialize DynamoDB client
const dynamoDB = new AWS.DynamoDB.DocumentClient();

// Middleware
app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: true }));

// Serve static files from the UI folder
app.use(express.static(path.join(__dirname, 'ui')));

// Authentication middleware
const authenticateToken = (req, res, next) => {
	const authHeader = req.headers['authorization'];
	const token = authHeader && authHeader.split(' ')[1];

	if (!token)
		return res
			.status(401)
			.json({ message: 'Authentication token is required' });

	jwt.verify(token, process.env.JWT_SECRET, (err, user) => {
		if (err)
			return res.status(403).json({ message: 'Invalid or expired token' });
		req.user = user;
		next();
	});
};

// Role-based authorization middleware
const authorize = (allowedRoles) => {
	return (req, res, next) => {
		if (!req.user)
			return res.status(401).json({ message: 'Authentication required' });

		if (allowedRoles.includes(req.user.role)) {
			next();
		} else {
			res.status(403).json({ message: 'Insufficient permissions' });
		}
	};
};

// Routes

// Registration endpoint
app.post('/api/register', async (req, res) => {
	const { username, password, email } = req.body;

	if (!username || !password || !email) {
		return res
			.status(400)
			.json({ message: 'Username, password, and email are required' });
	}

	try {
		// Check if user already exists
		const userCheckParams = {
			TableName: 'Users',
			Key: {
				username,
			},
		};

		const existingUser = await dynamoDB.get(userCheckParams).promise();

		if (existingUser.Item) {
			return res.status(409).json({ message: 'Username already exists' });
		}

		// Hash password
		const salt = await bcrypt.genSalt(10);
		const hashedPassword = await bcrypt.hash(password, salt);

		// Save user to DynamoDB
		const params = {
			TableName: 'Users',
			Item: {
				username,
				password: hashedPassword,
				email,
				role: 'user', // Default role
				createdAt: new Date().toISOString(),
			},
		};

		await dynamoDB.put(params).promise();

		res.status(201).json({ message: 'User registered successfully' });
	} catch (error) {
		console.error('Registration error:', error);
		res.status(500).json({ message: 'Server error during registration' });
	}
});

// Login endpoint
app.post('/api/login', async (req, res) => {
	const { username, password } = req.body;

	if (!username || !password) {
		return res
			.status(400)
			.json({ message: 'Username and password are required' });
	}

	try {
		// Get user from DynamoDB
		const params = {
			TableName: 'Users',
			Key: {
				username,
			},
		};

		const result = await dynamoDB.get(params).promise();
		const user = result.Item;

		if (!user) {
			return res.status(404).json({ message: 'User not found' });
		}

		// Compare passwords
		const isPasswordValid = await bcrypt.compare(password, user.password);

		if (!isPasswordValid) {
			return res.status(401).json({ message: 'Invalid password' });
		}

		// Generate JWT token
		const token = jwt.sign(
			{ username: user.username, role: user.role, email: user.email },
			process.env.JWT_SECRET,
			{ expiresIn: '24h' }
		);

		res.json({ token });
	} catch (error) {
		console.error('Login error:', error);
		res.status(500).json({ message: 'Server error during login' });
	}
});

// Protected route example
app.get('/api/profile', authenticateToken, async (req, res) => {
	try {
		// Get user from DynamoDB
		const params = {
			TableName: 'Users',
			Key: {
				username: req.user.username,
			},
			ProjectionExpression: 'username, email, role, createdAt',
		};

		const result = await dynamoDB.get(params).promise();

		if (!result.Item) {
			return res.status(404).json({ message: 'User not found' });
		}

		res.json(result.Item);
	} catch (error) {
		console.error('Profile error:', error);
		res.status(500).json({ message: 'Server error while fetching profile' });
	}
});

// Admin-only route example
app.get(
	'/api/admin/users',
	authenticateToken,
	authorize(['admin']),
	async (req, res) => {
		try {
			const params = {
				TableName: 'Users',
				ProjectionExpression: 'username, email, role, createdAt',
			};

			const result = await dynamoDB.scan(params).promise();

			res.json(result.Items);
		} catch (error) {
			console.error('Admin users error:', error);
			res.status(500).json({ message: 'Server error while fetching users' });
		}
	}
);

// Catch-all route to serve the UI's index.html
app.get('*', (req, res) => {
	res.sendFile(path.join(__dirname, 'ui', 'index.html'));
});

// Start server
app.listen(PORT, () => {
	console.log(`Server running on port ${PORT}`);
});
