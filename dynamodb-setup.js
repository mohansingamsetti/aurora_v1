const AWS = require('aws-sdk');
const dotenv = require('dotenv');

// Load environment variables
dotenv.config();

// Configure AWS
AWS.config.update({
	region: process.env.AWS_REGION || 'us-east-1',
	accessKeyId: process.env.AWS_ACCESS_KEY_ID,
	secretAccessKey: process.env.AWS_SECRET_ACCESS_KEY,
});

// Initialize DynamoDB client
const dynamoDB = new AWS.DynamoDB();

// Create Users table
const createUsersTable = async () => {
	const params = {
		TableName: 'Users',
		KeySchema: [
			{ AttributeName: 'username', KeyType: 'HASH' }, // Partition key
		],
		AttributeDefinitions: [{ AttributeName: 'username', AttributeType: 'S' }],
		ProvisionedThroughput: {
			ReadCapacityUnits: 5,
			WriteCapacityUnits: 5,
		},
	};

	try {
		const result = await dynamoDB.createTable(params).promise();
		console.log('Users table created:', result);
		return result;
	} catch (error) {
		if (error.code === 'ResourceInUseException') {
			console.log('Users table already exists');
		} else {
			console.error('Error creating Users table:', error);
			throw error;
		}
	}
};

// Create Sessions table (optional, for tracking active sessions)
const createSessionsTable = async () => {
	const params = {
		TableName: 'Sessions',
		KeySchema: [
			{ AttributeName: 'sessionId', KeyType: 'HASH' }, // Partition key
		],
		AttributeDefinitions: [
			{ AttributeName: 'sessionId', AttributeType: 'S' },
			{ AttributeName: 'username', AttributeType: 'S' },
		],
		GlobalSecondaryIndexes: [
			{
				IndexName: 'UsernameIndex',
				KeySchema: [{ AttributeName: 'username', KeyType: 'HASH' }],
				Projection: {
					ProjectionType: 'ALL',
				},
				ProvisionedThroughput: {
					ReadCapacityUnits: 5,
					WriteCapacityUnits: 5,
				},
			},
		],
		ProvisionedThroughput: {
			ReadCapacityUnits: 5,
			WriteCapacityUnits: 5,
		},
	};

	try {
		const result = await dynamoDB.createTable(params).promise();
		console.log('Sessions table created:', result);
		return result;
	} catch (error) {
		if (error.code === 'ResourceInUseException') {
			console.log('Sessions table already exists');
		} else {
			console.error('Error creating Sessions table:', error);
			throw error;
		}
	}
};

// Create an example Content table for your application's data
const createContentTable = async () => {
	const params = {
		TableName: 'Content',
		KeySchema: [
			{ AttributeName: 'id', KeyType: 'HASH' }, // Partition key
		],
		AttributeDefinitions: [
			{ AttributeName: 'id', AttributeType: 'S' },
			{ AttributeName: 'contentType', AttributeType: 'S' },
		],
		GlobalSecondaryIndexes: [
			{
				IndexName: 'ContentTypeIndex',
				KeySchema: [{ AttributeName: 'contentType', KeyType: 'HASH' }],
				Projection: {
					ProjectionType: 'ALL',
				},
				ProvisionedThroughput: {
					ReadCapacityUnits: 5,
					WriteCapacityUnits: 5,
				},
			},
		],
		ProvisionedThroughput: {
			ReadCapacityUnits: 5,
			WriteCapacityUnits: 5,
		},
	};

	try {
		const result = await dynamoDB.createTable(params).promise();
		console.log('Content table created:', result);
		return result;
	} catch (error) {
		if (error.code === 'ResourceInUseException') {
			console.log('Content table already exists');
		} else {
			console.error('Error creating Content table:', error);
			throw error;
		}
	}
};

// Create all tables
const createAllTables = async () => {
	try {
		await createUsersTable();
		await createSessionsTable();
		await createContentTable();
		console.log('All tables created successfully');
	} catch (error) {
		console.error('Error creating tables:', error);
	}
};

// Add admin user for initial access
const addAdminUser = async () => {
	const bcrypt = require('bcryptjs');
	const documentClient = new AWS.DynamoDB.DocumentClient();

	// Default admin credentials (change these in production)
	const adminUsername = process.env.ADMIN_USERNAME || 'admin';
	const adminPassword = process.env.ADMIN_PASSWORD || 'adminPassword123';
	const adminEmail = process.env.ADMIN_EMAIL || 'admin@example.com';

	try {
		// Check if admin already exists
		const checkParams = {
			TableName: 'Users',
			Key: {
				username: adminUsername,
			},
		};

		const existingAdmin = await documentClient.get(checkParams).promise();

		if (existingAdmin.Item) {
			console.log('Admin user already exists');
			return;
		}

		// Hash password
		const salt = await bcrypt.genSalt(10);
		const hashedPassword = await bcrypt.hash(adminPassword, salt);

		// Add admin user
		const params = {
			TableName: 'Users',
			Item: {
				username: adminUsername,
				password: hashedPassword,
				email: adminEmail,
				role: 'admin',
				createdAt: new Date().toISOString(),
			},
		};

		await documentClient.put(params).promise();
		console.log('Admin user created successfully');
	} catch (error) {
		console.error('Error creating admin user:', error);
	}
};

// Run setup
const runSetup = async () => {
	await createAllTables();
	await addAdminUser();
	console.log('DynamoDB setup completed');
};

// Run the setup if this file is executed directly
if (require.main === module) {
	runSetup();
}

module.exports = {
	createAllTables,
	addAdminUser,
	runSetup,
};
