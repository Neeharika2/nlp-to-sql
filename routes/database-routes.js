const router = require('express').Router();
const mysql = require('mysql2/promise');
const { Client: PgClient } = require('pg');
const { MongoClient } = require('mongodb');
const sql = require('mssql');

// Middleware to check if user is authenticated
const authCheck = (req, res, next) => {
  if (!req.isAuthenticated()) {
    return res.redirect('/auth/login');
  }
  next();
};

// Show database configuration page
router.get('/config', authCheck, (req, res) => {
  res.render('database-config');
});

// Handle database configuration and scan
router.post('/configure', authCheck, async (req, res) => {
  const { dbType } = req.body;
  
  console.log('Received form data:', req.body);
  
  // Validate required fields based on database type
  if (!dbType) {
    return res.status(400).send(`
      <h2>Error</h2>
      <p>Please select a database type.</p>
      <a href="/database/config">← Go Back</a>
    `);
  }
  
  try {
    let databases = [];
    
    switch (dbType) {
      case 'mysql':
        databases = await scanMySQL(req.body);
        break;
      case 'postgresql':
        databases = await scanPostgreSQL(req.body);
        break;
      case 'mssql':
        databases = await scanMSSQL(req.body);
        break;
      case 'mongodb':
        databases = await scanMongoDB(req.body);
        break;
      case 'mongodb-atlas':
        databases = await scanMongoDBAtlas(req.body);
        break;
      case 'firebase':
        databases = await scanFirebase(req.body);
        break;
      case 'supabase':
        databases = await scanSupabase(req.body);
        break;
      case 'aws-rds':
        databases = await scanAWSRDS(req.body);
        break;
      case 'digitalocean':
        databases = await scanDigitalOcean(req.body);
        break;
      default:
        throw new Error('Unsupported database type');
    }
    
    // Store connection details in session
    req.session.dbConfig = req.body;
    
    res.render('database-select', {
      dbType,
      databases,
      host: req.body.host || req.body.endpoint || 'Cloud',
    });
  } catch (error) {
    console.error('Database connection error:', error);
    res.status(500).send(`
      <h2>Connection Failed</h2>
      <p>${error.message}</p>
      <a href="/database/config">← Go Back</a>
    `);
  }
});

// Handle database selection
router.post('/select', authCheck, (req, res) => {
  const { selectedDatabase, dbType } = req.body;
  
  // Store selected database in session
  req.session.selectedDatabase = selectedDatabase;
  req.session.dbType = dbType;
  
  // Redirect to query interface
  res.redirect('/query');
});

// MySQL Scanner
async function scanMySQL(config) {
  if (!config.host || !config.username || !config.password) {
    throw new Error('Missing required fields: host, username, and password are required for MySQL');
  }
  
  const connection = await mysql.createConnection({
    host: config.host,
    port: parseInt(config.port) || 3306,
    user: config.username,
    password: config.password,
  });
  
  const [rows] = await connection.execute('SHOW DATABASES');
  await connection.end();
  
  return rows.map(row => ({
    name: row.Database,
    type: 'mysql'
  }));
}

// PostgreSQL Scanner
async function scanPostgreSQL(config) {
  if (!config.host || !config.username || !config.password) {
    throw new Error('Missing required fields: host, username, and password are required for PostgreSQL');
  }
  
  const client = new PgClient({
    host: config.host,
    port: parseInt(config.port) || 5432,
    user: config.username,
    password: config.password,
    database: 'postgres'
  });
  
  await client.connect();
  const result = await client.query(`
    SELECT datname FROM pg_database 
    WHERE datistemplate = false AND datname != 'postgres'
  `);
  await client.end();
  
  return result.rows.map(row => ({
    name: row.datname,
    type: 'postgresql'
  }));
}

// MSSQL Scanner
async function scanMSSQL(config) {
  if (!config.host || !config.username || !config.password) {
    throw new Error('Missing required fields: host, username, and password are required for MSSQL');
  }
  
  const pool = await sql.connect({
    server: config.host,
    port: parseInt(config.port) || 1433,
    user: config.username,
    password: config.password,
    options: {
      encrypt: true,
      trustServerCertificate: true
    }
  });
  
  const result = await pool.request().query('SELECT name FROM sys.databases');
  await pool.close();
  
  return result.recordset.map(row => ({
    name: row.name,
    type: 'mssql'
  }));
}

// MongoDB Scanner
async function scanMongoDB(config) {
  if (!config.host) {
    throw new Error('Missing required field: host is required for MongoDB');
  }
  
  const auth = config.username && config.password ? `${config.username}:${config.password}@` : '';
  const url = `mongodb://${auth}${config.host}:${config.port || 27017}`;
  
  const client = new MongoClient(url);
  await client.connect();
  
  const adminDb = client.db().admin();
  const { databases } = await adminDb.listDatabases();
  
  await client.close();
  
  return databases.map(db => ({
    name: db.name,
    size: `${(db.sizeOnDisk / 1024 / 1024).toFixed(2)} MB`,
    type: 'mongodb'
  }));
}

// MongoDB Atlas Scanner
async function scanMongoDBAtlas(config) {
  if (!config.connectionString) {
    throw new Error('Missing required field: connection string is required for MongoDB Atlas');
  }
  
  const client = new MongoClient(config.connectionString);
  await client.connect();
  
  const adminDb = client.db().admin();
  const { databases } = await adminDb.listDatabases();
  
  await client.close();
  
  return databases.map(db => ({
    name: db.name,
    size: `${(db.sizeOnDisk / 1024 / 1024).toFixed(2)} MB`,
    type: 'mongodb-atlas'
  }));
}

// Firebase Scanner (Firestore)
async function scanFirebase(config) {
  // Firebase doesn't have "databases" in the traditional sense
  // Return the project as a single database
  return [{
    name: config.projectId,
    type: 'firebase',
    tables: 'Firestore Collections'
  }];
}

// Supabase Scanner
async function scanSupabase(config) {
  // Supabase is PostgreSQL-based, returns the public schema by default
  return [{
    name: 'public',
    type: 'supabase',
    tables: 'PostgreSQL Database'
  }];
}

// AWS RDS Scanner
async function scanAWSRDS(config) {
  if (config.awsEngine === 'mysql') {
    const connection = await mysql.createConnection({
      host: config.endpoint,
      port: config.port || 3306,
      user: config.username,
      password: config.password,
    });
    
    const [rows] = await connection.execute('SHOW DATABASES');
    await connection.end();
    
    return rows.map(row => ({
      name: row.Database,
      type: 'aws-rds-mysql'
    }));
  } else if (config.awsEngine === 'postgresql') {
    const client = new PgClient({
      host: config.endpoint,
      port: config.port || 5432,
      user: config.username,
      password: config.password,
      database: 'postgres'
    });
    
    await client.connect();
    const result = await client.query(`
      SELECT datname FROM pg_database 
      WHERE datistemplate = false AND datname != 'postgres'
    `);
    await client.end();
    
    return result.rows.map(row => ({
      name: row.datname,
      type: 'aws-rds-postgresql'
    }));
  }
  
  return [];
}

// DigitalOcean Scanner
async function scanDigitalOcean(config) {
  const sslConfig = config.sslRequired ? { rejectUnauthorized: false } : false;
  
  if (config.doEngine === 'mysql') {
    const connection = await mysql.createConnection({
      host: config.host,
      port: config.port || 25060,
      user: config.username,
      password: config.password,
      ssl: sslConfig
    });
    
    const [rows] = await connection.execute('SHOW DATABASES');
    await connection.end();
    
    return rows.map(row => ({
      name: row.Database,
      type: 'digitalocean-mysql'
    }));
  } else if (config.doEngine === 'postgresql') {
    const client = new PgClient({
      host: config.host,
      port: config.port || 25060,
      user: config.username,
      password: config.password,
      database: config.database || 'defaultdb',
      ssl: sslConfig
    });
    
    await client.connect();
    const result = await client.query(`
      SELECT datname FROM pg_database 
      WHERE datistemplate = false
    `);
    await client.end();
    
    return result.rows.map(row => ({
      name: row.datname,
      type: 'digitalocean-postgresql'
    }));
  } else if (config.doEngine === 'mongodb') {
    const sslParam = config.sslRequired ? '&ssl=true&replicaSet=db&authSource=admin' : '';
    const url = `mongodb://${config.username}:${encodeURIComponent(config.password)}@${config.host}:${config.port}/${config.database || 'admin'}?tls=true${sslParam}`;
    
    const client = new MongoClient(url, {
      tls: true,
      tlsAllowInvalidCertificates: true
    });
    await client.connect();
    
    const adminDb = client.db().admin();
    const { databases } = await adminDb.listDatabases();
    
    await client.close();
    
    return databases.map(db => ({
      name: db.name,
      size: `${(db.sizeOnDisk / 1024 / 1024).toFixed(2)} MB`,
      type: 'digitalocean-mongodb'
    }));
  } else if (config.doEngine === 'redis') {
    // Redis doesn't have traditional databases in the same way
    // Return Redis database numbers (0-15 by default)
    return Array.from({ length: 16 }, (_, i) => ({
      name: `db${i}`,
      type: 'digitalocean-redis',
      tables: 'Redis Key-Value Store'
    }));
  }
  
  return [];
}

module.exports = router;
