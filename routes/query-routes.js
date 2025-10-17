const router = require('express').Router();
const { GoogleGenerativeAI } = require('@google/generative-ai');
const mysql = require('mysql2/promise');
const { Client: PgClient } = require('pg');
const { MongoClient } = require('mongodb');
const sql = require('mssql');
const { createClient } = require('@supabase/supabase-js');

// Middleware to check if user is authenticated
const authCheck = (req, res, next) => {
  if (!req.isAuthenticated()) {
    return res.redirect('/auth/login');
  }
  next();
};

// Show query interface
router.get('/', authCheck, (req, res) => {
  if (!req.session.selectedDatabase || !req.session.dbType) {
    return res.redirect('/database/config');
  }
  
  res.render('query-interface', {
    dbType: req.session.dbType,
    selectedDatabase: req.session.selectedDatabase
  });
});

// Execute natural language query
router.post('/execute', authCheck, async (req, res) => {
  const { nlQuery } = req.body;
  const dbConfig = req.session.dbConfig;
  const dbType = req.session.dbType;
  const selectedDatabase = req.session.selectedDatabase;
  
  if (!dbConfig || !dbType || !selectedDatabase) {
    return res.json({ success: false, error: 'Database not configured. Please configure your database first.' });
  }
  
  try {
    // Get database schema
    const schema = await getDatabaseSchema(dbType, dbConfig, selectedDatabase);
    
    // Convert natural language to SQL using Gemini
    const sqlQuery = await convertToSQL(nlQuery, schema, dbType);
    
    // Execute the query
    const results = await executeQuery(sqlQuery, dbType, dbConfig, selectedDatabase);
    
    res.json({
      success: true,
      sqlQuery: sqlQuery,
      results: results
    });
  } catch (error) {
    console.error('Query execution error:', error);
    res.json({
      success: false,
      error: error.message
    });
  }
});

// Convert natural language to SQL using Gemini API
async function convertToSQL(nlQuery, schema, dbType) {
  const genAI = new GoogleGenerativeAI(process.env.GEMINI_API_KEY);
  const model = genAI.getGenerativeModel({ model: "gemini-2.5-flash" });
  
  const prompt = `You are a SQL query generator. Convert the following natural language query into a valid ${dbType.toUpperCase()} SQL query.

Database Schema:
${schema}

Natural Language Query: ${nlQuery}

Instructions:
1. Generate ONLY the SQL query, nothing else
2. Do not include explanations, markdown formatting, or code blocks
3. Use proper ${dbType.toUpperCase()} syntax
4. Return only executable SQL
5. For SELECT queries, limit results to 100 rows if no limit is specified
6. Use appropriate JOIN clauses when needed
7. Ensure the query is safe and does not include DROP, DELETE, or UPDATE unless explicitly requested

SQL Query:`;
  
  const result = await model.generateContent(prompt);
  const response = await result.response;
  let sqlQuery = response.text().trim();
  
  // Clean up the response - remove markdown code blocks if present
  sqlQuery = sqlQuery.replace(/```sql\n?/g, '').replace(/```\n?/g, '').trim();
  
  // Remove any trailing semicolon for consistency
  sqlQuery = sqlQuery.replace(/;+$/, '');
  
  return sqlQuery;
}

// Get database schema
async function getDatabaseSchema(dbType, config, database) {
  try {
    switch (dbType) {
      case 'mysql':
        return await getMySQLSchema(config, database);
      case 'postgresql':
        return await getPostgreSQLSchema(config, database);
      case 'mssql':
        return await getMSSQLSchema(config, database);
      case 'mongodb':
      case 'mongodb-atlas':
        return await getMongoDBSchema(config, database);
      case 'firebase':
        return await getFirebaseSchema(config, database);
      case 'supabase':
        return await getSupabaseSchema(config, database);
      case 'aws-rds':
        return await getAWSRDSSchema(config, database);
      case 'digitalocean':
        return await getDigitalOceanSchema(config, database);
      default:
        return 'Schema information not available';
    }
  } catch (error) {
    console.error('Error fetching schema:', error);
    throw new Error('Failed to fetch database schema: ' + error.message);
  }
}

// MySQL Schema
async function getMySQLSchema(config, database) {
  const connection = await mysql.createConnection({
    host: config.host,
    port: parseInt(config.port) || 3306,
    user: config.username,
    password: config.password,
    database: database
  });
  
  const [tables] = await connection.execute('SHOW TABLES');
  let schema = `Database: ${database}\n\nTables:\n`;
  
  for (const table of tables) {
    const tableName = table[`Tables_in_${database}`];
    const [columns] = await connection.execute(`DESCRIBE ${tableName}`);
    schema += `\nTable: ${tableName}\n`;
    columns.forEach(col => {
      schema += `  - ${col.Field} (${col.Type}) ${col.Key === 'PRI' ? 'PRIMARY KEY' : ''}\n`;
    });
  }
  
  await connection.end();
  return schema;
}

// PostgreSQL Schema
async function getPostgreSQLSchema(config, database) {
  const client = new PgClient({
    host: config.host,
    port: parseInt(config.port) || 5432,
    user: config.username,
    password: config.password,
    database: database
  });
  
  await client.connect();
  
  const result = await client.query(`
    SELECT table_name 
    FROM information_schema.tables 
    WHERE table_schema = 'public'
  `);
  
  let schema = `Database: ${database}\n\nTables:\n`;
  
  for (const row of result.rows) {
    const tableName = row.table_name;
    const colResult = await client.query(`
      SELECT column_name, data_type, is_nullable
      FROM information_schema.columns
      WHERE table_name = $1
    `, [tableName]);
    
    schema += `\nTable: ${tableName}\n`;
    colResult.rows.forEach(col => {
      schema += `  - ${col.column_name} (${col.data_type}) ${col.is_nullable === 'NO' ? 'NOT NULL' : ''}\n`;
    });
  }
  
  await client.end();
  return schema;
}

// MSSQL Schema
async function getMSSQLSchema(config, database) {
  const pool = await sql.connect({
    server: config.host,
    port: parseInt(config.port) || 1433,
    user: config.username,
    password: config.password,
    database: database,
    options: {
      encrypt: true,
      trustServerCertificate: true
    }
  });
  
  const result = await pool.request().query(`
    SELECT TABLE_NAME 
    FROM INFORMATION_SCHEMA.TABLES 
    WHERE TABLE_TYPE = 'BASE TABLE'
  `);
  
  let schema = `Database: ${database}\n\nTables:\n`;
  
  for (const row of result.recordset) {
    const tableName = row.TABLE_NAME;
    const colResult = await pool.request().query(`
      SELECT COLUMN_NAME, DATA_TYPE, IS_NULLABLE
      FROM INFORMATION_SCHEMA.COLUMNS
      WHERE TABLE_NAME = @tableName
    `, { tableName: tableName });
    
    schema += `\nTable: ${tableName}\n`;
    colResult.recordset.forEach(col => {
      schema += `  - ${col.COLUMN_NAME} (${col.DATA_TYPE}) ${col.IS_NULLABLE === 'NO' ? 'NOT NULL' : ''}\n`;
    });
  }
  
  await pool.close();
  return schema;
}

// MongoDB Schema (approximate)
async function getMongoDBSchema(config, database) {
  let client;
  
  if (config.connectionString) {
    client = new MongoClient(config.connectionString);
  } else {
    const auth = config.username && config.password ? `${config.username}:${config.password}@` : '';
    const url = `mongodb://${auth}${config.host}:${config.port || 27017}`;
    client = new MongoClient(url);
  }
  
  await client.connect();
  const db = client.db(database);
  const collections = await db.listCollections().toArray();
  
  let schema = `Database: ${database}\n\nCollections:\n`;
  
  for (const collection of collections) {
    schema += `\nCollection: ${collection.name}\n`;
    const sample = await db.collection(collection.name).findOne();
    if (sample) {
      schema += '  Sample fields:\n';
      Object.keys(sample).forEach(key => {
        schema += `  - ${key} (${typeof sample[key]})\n`;
      });
    }
  }
  
  await client.close();
  return schema;
}

// Firebase Schema (Firestore)
async function getFirebaseSchema(config, database) {
  // Firebase Firestore doesn't have a fixed schema
  // Return a basic structure
  return `Database: ${database} (Firebase Firestore)

Note: Firestore is a NoSQL document database with flexible schema.
Collections are created dynamically when documents are added.

For querying, specify collection names directly in your query.
Example: "Show all documents from users collection"`;
}

// Supabase Schema (PostgreSQL-based)
async function getSupabaseSchema(config, database) {
  if (!config.supabaseUrl || !config.supabaseKey) {
    throw new Error('Missing Supabase URL or Key');
  }

  const supabase = createClient(config.supabaseUrl, config.supabaseKey);

  try {
    // Query the information_schema using Supabase's PostgreSQL connection
    const { data: tables, error: tablesError } = await supabase
      .from('information_schema.tables')
      .select('table_name')
      .eq('table_schema', 'public')
      .eq('table_type', 'BASE TABLE');

    if (tablesError) {
      // Fallback: Use RPC to get schema information
      const { data: rpcTables, error: rpcError } = await supabase.rpc('get_schema_info');
      
      if (rpcError) {
        // If RPC fails, use direct PostgreSQL connection
        return await getSupabaseSchemaViaPostgres(config, database);
      }
      
      return formatSupabaseSchema(rpcTables, database);
    }

    let schema = `Database: ${database} (Supabase/PostgreSQL)\n\nTables:\n`;

    // Get column information for each table
    for (const table of tables || []) {
      const tableName = table.table_name;
      
      const { data: columns, error: columnsError } = await supabase
        .from('information_schema.columns')
        .select('column_name, data_type, is_nullable, column_default')
        .eq('table_schema', 'public')
        .eq('table_name', tableName);

      schema += `\nTable: ${tableName}\n`;
      
      if (columns && !columnsError) {
        columns.forEach(col => {
          const nullable = col.is_nullable === 'YES' ? 'NULL' : 'NOT NULL';
          const defaultVal = col.column_default ? ` DEFAULT ${col.column_default}` : '';
          schema += `  - ${col.column_name} (${col.data_type}) ${nullable}${defaultVal}\n`;
        });
      } else {
        // Fallback: Get table structure via select
        const { data: sampleData, error: sampleError } = await supabase
          .from(tableName)
          .select('*')
          .limit(1);

        if (sampleData && sampleData.length > 0 && !sampleError) {
          Object.keys(sampleData[0]).forEach(key => {
            const value = sampleData[0][key];
            const type = typeof value;
            schema += `  - ${key} (${type})\n`;
          });
        }
      }
    }

    return schema;
  } catch (error) {
    console.error('Error fetching Supabase schema:', error);
    // Fallback to PostgreSQL connection if Supabase client fails
    return await getSupabaseSchemaViaPostgres(config, database);
  }
}

// Fallback method using direct PostgreSQL connection
async function getSupabaseSchemaViaPostgres(config, database) {
  // Extract host from Supabase URL
  // Supabase URL format: https://xxxxx.supabase.co
  const supabaseHost = config.supabaseUrl.replace('https://', '').replace('http://', '');
  const dbHost = `db.${supabaseHost.split('.')[0]}.supabase.co`;

  try {
    const client = new PgClient({
      host: dbHost,
      port: 5432,
      user: 'postgres',
      password: config.supabasePassword || config.supabaseKey, // May need database password
      database: 'postgres',
      ssl: { rejectUnauthorized: false }
    });

    await client.connect();

    const result = await client.query(`
      SELECT table_name 
      FROM information_schema.tables 
      WHERE table_schema = 'public' AND table_type = 'BASE TABLE'
    `);

    let schema = `Database: ${database} (Supabase/PostgreSQL)\n\nTables:\n`;

    for (const row of result.rows) {
      const tableName = row.table_name;
      const colResult = await client.query(`
        SELECT column_name, data_type, is_nullable, column_default
        FROM information_schema.columns
        WHERE table_name = $1 AND table_schema = 'public'
        ORDER BY ordinal_position
      `, [tableName]);

      schema += `\nTable: ${tableName}\n`;
      colResult.rows.forEach(col => {
        const nullable = col.is_nullable === 'YES' ? 'NULL' : 'NOT NULL';
        const defaultVal = col.column_default ? ` DEFAULT ${col.column_default}` : '';
        schema += `  - ${col.column_name} (${col.data_type}) ${nullable}${defaultVal}\n`;
      });
    }

    await client.end();
    return schema;
  } catch (pgError) {
    console.error('PostgreSQL connection also failed:', pgError);
    
    // Return basic schema info
    return `Database: ${database} (Supabase/PostgreSQL)

Supabase is PostgreSQL-based with the following features:
- Real-time subscriptions
- Row Level Security (RLS)
- RESTful API access
- Built-in authentication

Unable to fetch detailed schema. Please check:
1. Supabase URL and Key are correct
2. Database password is provided if needed
3. Network connectivity to Supabase

You can still query by specifying table names directly.`;
  }
}

function formatSupabaseSchema(schemaData, database) {
  let schema = `Database: ${database} (Supabase/PostgreSQL)\n\nTables:\n`;
  
  if (Array.isArray(schemaData)) {
    schemaData.forEach(table => {
      schema += `\nTable: ${table.table_name}\n`;
      if (table.columns) {
        table.columns.forEach(col => {
          schema += `  - ${col.column_name} (${col.data_type})\n`;
        });
      }
    });
  }
  
  return schema;
}

// Execute query
async function executeQuery(sqlQuery, dbType, config, database) {
  switch (dbType) {
    case 'mysql':
      return await executeMySQLQuery(sqlQuery, config, database);
    case 'postgresql':
      return await executePostgreSQLQuery(sqlQuery, config, database);
    case 'mssql':
      return await executeMSSQLQuery(sqlQuery, config, database);
    case 'mongodb':
    case 'mongodb-atlas':
      return await executeMongoDBQuery(sqlQuery, config, database);
    case 'firebase':
      throw new Error('Firebase query execution is not yet implemented. Please use Firebase SDK directly.');
    case 'supabase':
      return await executeSupabaseQuery(sqlQuery, config, database);
    case 'aws-rds':
      return await executeAWSRDSQuery(sqlQuery, config, database);
    case 'digitalocean':
      return await executeDigitalOceanQuery(sqlQuery, config, database);
    default:
      throw new Error('Unsupported database type');
  }
}

// Execute MySQL Query
async function executeMySQLQuery(sqlQuery, config, database) {
  const connection = await mysql.createConnection({
    host: config.host,
    port: parseInt(config.port) || 3306,
    user: config.username,
    password: config.password,
    database: database
  });
  
  const [rows] = await connection.execute(sqlQuery);
  await connection.end();
  
  return rows;
}

// Execute PostgreSQL Query
async function executePostgreSQLQuery(sqlQuery, config, database) {
  const client = new PgClient({
    host: config.host,
    port: parseInt(config.port) || 5432,
    user: config.username,
    password: config.password,
    database: database
  });
  
  await client.connect();
  const result = await client.query(sqlQuery);
  await client.end();
  
  return result.rows;
}

// Execute MSSQL Query
async function executeMSSQLQuery(sqlQuery, config, database) {
  const pool = await sql.connect({
    server: config.host,
    port: parseInt(config.port) || 1433,
    user: config.username,
    password: config.password,
    database: database,
    options: {
      encrypt: true,
      trustServerCertificate: true
    }
  });
  
  const result = await pool.request().query(sqlQuery);
  await pool.close();
  
  return result.recordset;
}

// Execute MongoDB Query (convert SQL-like to MongoDB query)
async function executeMongoDBQuery(sqlQuery, config, database) {
  // This is simplified - you might want to use a proper SQL-to-MongoDB converter
  throw new Error('MongoDB query execution from SQL is not yet implemented. Please use MongoDB syntax directly.');
}

// Execute Supabase Query (PostgreSQL-based)
async function executeSupabaseQuery(sqlQuery, config, database) {
  if (!config.supabaseUrl || !config.supabaseKey) {
    throw new Error('Missing Supabase URL or Key');
  }

  const supabase = createClient(config.supabaseUrl, config.supabaseKey);

  try {
    // Parse the SQL query to extract table name and conditions
    const queryInfo = parseSelectQuery(sqlQuery);

    if (!queryInfo.tableName) {
      throw new Error('Unable to parse table name from query. Please use standard SELECT syntax.');
    }

    // Build Supabase query
    let query = supabase.from(queryInfo.tableName).select(queryInfo.columns || '*');

    // Apply filters if any
    if (queryInfo.where) {
      queryInfo.where.forEach(condition => {
        if (condition.operator === '=') {
          query = query.eq(condition.column, condition.value);
        } else if (condition.operator === '>') {
          query = query.gt(condition.column, condition.value);
        } else if (condition.operator === '<') {
          query = query.lt(condition.column, condition.value);
        } else if (condition.operator === '>=') {
          query = query.gte(condition.column, condition.value);
        } else if (condition.operator === '<=') {
          query = query.lte(condition.column, condition.value);
        } else if (condition.operator === 'LIKE') {
          query = query.like(condition.column, condition.value);
        }
      });
    }

    // Apply limit
    if (queryInfo.limit) {
      query = query.limit(queryInfo.limit);
    }

    // Apply order
    if (queryInfo.orderBy) {
      query = query.order(queryInfo.orderBy.column, { 
        ascending: queryInfo.orderBy.direction !== 'DESC' 
      });
    }

    const { data, error } = await query;

    if (error) {
      throw new Error(`Supabase query error: ${error.message}`);
    }

    return data || [];
  } catch (error) {
    console.error('Supabase query execution error:', error);
    // Fallback to PostgreSQL direct connection
    return await executeSupabaseQueryViaPostgres(sqlQuery, config, database);
  }
}

// Fallback to PostgreSQL connection for complex queries
async function executeSupabaseQueryViaPostgres(sqlQuery, config, database) {
  const supabaseHost = config.supabaseUrl.replace('https://', '').replace('http://', '');
  const dbHost = `db.${supabaseHost.split('.')[0]}.supabase.co`;

  const client = new PgClient({
    host: dbHost,
    port: 5432,
    user: 'postgres',
    password: config.supabasePassword || config.supabaseKey,
    database: 'postgres',
    ssl: { rejectUnauthorized: false }
  });

  try {
    await client.connect();
    const result = await client.query(sqlQuery);
    return result.rows;
  } finally {
    await client.end();
  }
}

// Simple SQL parser for Supabase queries
function parseSelectQuery(sqlQuery) {
  const query = sqlQuery.trim().toUpperCase();
  const originalQuery = sqlQuery.trim();
  
  const info = {
    tableName: null,
    columns: '*',
    where: [],
    limit: 100,
    orderBy: null
  };

  // Extract table name
  const fromMatch = originalQuery.match(/FROM\s+([`"]?)(\w+)\1/i);
  if (fromMatch) {
    info.tableName = fromMatch[2];
  }

  // Extract columns
  const selectMatch = originalQuery.match(/SELECT\s+(.*?)\s+FROM/i);
  if (selectMatch && selectMatch[1].trim() !== '*') {
    info.columns = selectMatch[1].trim();
  }

  // Extract WHERE conditions (simplified)
  const whereMatch = originalQuery.match(/WHERE\s+(.*?)(?:\s+ORDER|\s+LIMIT|$)/i);
  if (whereMatch) {
    const conditions = whereMatch[1].split(/\s+AND\s+/i);
    conditions.forEach(cond => {
      const condMatch = cond.match(/(\w+)\s*(=|>|<|>=|<=|LIKE)\s*[']?(.*?)[']?$/i);
      if (condMatch) {
        info.where.push({
          column: condMatch[1],
          operator: condMatch[2].toUpperCase(),
          value: condMatch[3].replace(/['"]/g, '')
        });
      }
    });
  }

  // Extract LIMIT
  const limitMatch = originalQuery.match(/LIMIT\s+(\d+)/i);
  if (limitMatch) {
    info.limit = parseInt(limitMatch[1]);
  }

  // Extract ORDER BY
  const orderMatch = originalQuery.match(/ORDER\s+BY\s+(\w+)(?:\s+(ASC|DESC))?/i);
  if (orderMatch) {
    info.orderBy = {
      column: orderMatch[1],
      direction: orderMatch[2] ? orderMatch[2].toUpperCase() : 'ASC'
    };
  }

  return info;
}

module.exports = router;
