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

const userRoutes = require('./routes');

app.use('/api/user', userRoutes);

// Catch-all route to serve the UI's index.html
app.get('/', (_, res) => {
	res.sendFile(path.join(__dirname, 'ui', 'index.html'));
});

// Start server
app.listen(PORT, () => {
	console.log(`Server running on port ${PORT}`);
});
