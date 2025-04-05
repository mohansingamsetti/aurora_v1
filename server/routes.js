const express = require('express');
const router = express.Router();
const { createClient } = require('@supabase/supabase-js');

// Initialize Supabase client
const supabaseUrl = process.env.SUPABASE_URL;
const supabaseKey = process.env.SUPABASE_SERVICE_KEY;
const supabase = createClient(supabaseUrl, supabaseKey);

// Authentication middleware (imported from main file or auth module)
const authenticateToken = async (req, res, next) => {
	const authHeader = req.headers['authorization'];
	const token = authHeader && authHeader.split(' ')[1];

	if (!token)
		return res
			.status(401)
			.json({ message: 'Authentication token is required' });

	try {
		// For Supabase tokens
		const { data, error } = await supabase.auth.getUser(token);

		if (error) {
			return res.status(403).json({ message: 'Invalid or expired token' });
		}

		// Get user role from the users table
		const { data: userData, error: userError } = await supabase
			.from('users')
			.select('role')
			.eq('id', data.user.id)
			.single();

		if (userError) {
			return res.status(500).json({ message: 'Error fetching user data' });
		}

		// Attach user data to the request
		req.user = {
			id: data.user.id,
			email: data.user.email,
			role: userData?.role || 'user',
		};

		next();
	} catch (error) {
		console.error('Auth error:', error);
		res.status(403).json({ message: 'Invalid or expired token' });
	}
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

// Authentication Routes

// Registration endpoint
router.post('/register', async (req, res) => {
	const { email, password, username } = req.body;

	if (!email || !password) {
		return res.status(400).json({ message: 'Email and password are required' });
	}

	try {
		// Register with Supabase Auth
		const { data: authData, error: authError } = await supabase.auth.signUp({
			email,
			password,
			options: {
				data: {
					username: username || email.split('@')[0],
				},
			},
		});

		if (authError) {
			return res.status(400).json({ message: authError.message });
		}

		// Add user to users table with role
		if (authData.user) {
			const { error: insertError } = await supabase.from('users').insert([
				{
					id: authData.user.id,
					username: username || email.split('@')[0],
					email,
					role: 'user',
					created_at: new Date().toISOString(),
				},
			]);

			if (insertError) {
				console.error('Error inserting user data:', insertError);
				// Don't return here, as the auth account is already created
			}
		}

		res.status(201).json({
			message:
				'User registered successfully. Please check your email for confirmation.',
			user: {
				id: authData.user.id,
				email: authData.user.email,
			},
		});
	} catch (error) {
		console.error('Registration error:', error);
		res.status(500).json({ message: 'Server error during registration' });
	}
});

// Login endpoint
router.post('/login', async (req, res) => {
	const { email, password } = req.body;

	if (!email || !password) {
		return res.status(400).json({ message: 'Email and password are required' });
	}

	try {
		// Sign in with Supabase Auth
		const { data, error } = await supabase.auth.signInWithPassword({
			email,
			password,
		});

		if (error) {
			return res.status(401).json({ message: error.message });
		}

		// Get user role
		const { data: userData, error: userError } = await supabase
			.from('users')
			.select('role, username')
			.eq('id', data.user.id)
			.single();

		// Return token and user data
		res.json({
			session: data.session,
			user: {
				id: data.user.id,
				email: data.user.email,
				role: userData?.role || 'user',
				username: userData?.username || data.user.email.split('@')[0],
			},
		});
	} catch (error) {
		console.error('Login error:', error);
		res.status(500).json({ message: 'Server error during login' });
	}
});

// Logout endpoint
router.post('/logout', async (req, res) => {
	const authHeader = req.headers['authorization'];
	const token = authHeader && authHeader.split(' ')[1];

	if (!token) {
		return res.status(200).json({ message: 'Already logged out' });
	}

	try {
		const { error } = await supabase.auth.signOut();

		if (error) {
			return res.status(500).json({ message: error.message });
		}

		res.json({ message: 'Logged out successfully' });
	} catch (error) {
		console.error('Logout error:', error);
		res.status(500).json({ message: 'Server error during logout' });
	}
});

// Password reset request
router.post('/forgot-password', async (req, res) => {
	const { email } = req.body;

	if (!email) {
		return res.status(400).json({ message: 'Email is required' });
	}

	try {
		const { error } = await supabase.auth.resetPasswordForEmail(email, {
			redirectTo: `${process.env.FRONTEND_URL}/reset-password`,
		});

		if (error) {
			return res.status(400).json({ message: error.message });
		}

		res.json({ message: 'Password reset email sent' });
	} catch (error) {
		console.error('Forgot password error:', error);
		res
			.status(500)
			.json({ message: 'Server error sending password reset email' });
	}
});

// User Profile Routes

// Get current user profile
router.get('/profile', authenticateToken, async (req, res) => {
	try {
		// Get user profile data
		const { data, error } = await supabase
			.from('users')
			.select('username, email, role, created_at')
			.eq('id', req.user.id)
			.single();

		if (error) {
			return res.status(404).json({ message: 'User not found' });
		}

		res.json(data);
	} catch (error) {
		console.error('Profile error:', error);
		res.status(500).json({ message: 'Server error while fetching profile' });
	}
});

// Update user profile
router.put('/profile', authenticateToken, async (req, res) => {
	const { username } = req.body;

	if (!username) {
		return res.status(400).json({ message: 'Username is required' });
	}

	try {
		// Update user in users table
		const { data, error } = await supabase
			.from('users')
			.update({ username })
			.eq('id', req.user.id)
			.select()
			.single();

		if (error) {
			return res.status(400).json({ message: error.message });
		}

		res.json(data);
	} catch (error) {
		console.error('Update profile error:', error);
		res.status(500).json({ message: 'Server error while updating profile' });
	}
});

// Change password
router.post('/change-password', authenticateToken, async (req, res) => {
	const { password } = req.body;

	if (!password) {
		return res.status(400).json({ message: 'Password is required' });
	}

	try {
		const { error } = await supabase.auth.admin.updateUserById(req.user.id, {
			password,
		});

		if (error) {
			return res.status(400).json({ message: error.message });
		}

		res.json({ message: 'Password updated successfully' });
	} catch (error) {
		console.error('Change password error:', error);
		res.status(500).json({ message: 'Server error while changing password' });
	}
});

// Admin Routes

// Get all users (admin only)
router.get(
	'/admin/users',
	authenticateToken,
	authorize(['admin']),
	async (req, res) => {
		try {
			const { data, error } = await supabase
				.from('users')
				.select('id, username, email, role, created_at');

			if (error) {
				return res.status(500).json({ message: error.message });
			}

			res.json(data);
		} catch (error) {
			console.error('Admin users error:', error);
			res.status(500).json({ message: 'Server error while fetching users' });
		}
	}
);

// Update user role (admin only)
router.put(
	'/admin/users/:id/role',
	authenticateToken,
	authorize(['admin']),
	async (req, res) => {
		const userId = req.params.id;
		const { role } = req.body;

		if (!role || !['user', 'admin'].includes(role)) {
			return res
				.status(400)
				.json({ message: 'Valid role is required (user or admin)' });
		}

		try {
			const { data, error } = await supabase
				.from('users')
				.update({ role })
				.eq('id', userId)
				.select()
				.single();

			if (error) {
				return res.status(400).json({ message: error.message });
			}

			res.json(data);
		} catch (error) {
			console.error('Update role error:', error);
			res
				.status(500)
				.json({ message: 'Server error while updating user role' });
		}
	}
);

// Delete user (admin only)
router.delete(
	'/admin/users/:id',
	authenticateToken,
	authorize(['admin']),
	async (req, res) => {
		const userId = req.params.id;

		try {
			// Delete from users table first (to maintain referential integrity)
			const { error: userDeleteError } = await supabase
				.from('users')
				.delete()
				.eq('id', userId);

			if (userDeleteError) {
				return res.status(400).json({ message: userDeleteError.message });
			}

			// Delete the auth user
			const { error: authDeleteError } = await supabase.auth.admin.deleteUser(
				userId
			);

			if (authDeleteError) {
				console.error('Error deleting auth user:', authDeleteError);
				return res
					.status(500)
					.json({
						message: 'User deleted from database but not from auth system',
					});
			}

			res.json({ message: 'User deleted successfully' });
		} catch (error) {
			console.error('Delete user error:', error);
			res.status(500).json({ message: 'Server error while deleting user' });
		}
	}
);

module.exports = router;
