const { columnSecurity, userRole, safeAlternatives } = require('../config/security-config');

class SecurityValidator {
  constructor() {
    this.userRole = userRole; // Single admin role
    this.blockedColumns = [];
    this.warnings = [];
  }

  // Check if a column is sensitive/blocked
  isSensitiveColumn(columnName) {
    const lowerColumn = columnName.toLowerCase();
    
    // Check if column matches any blocked pattern
    const isBlocked = columnSecurity.blocked.some(blocked => 
      lowerColumn.includes(blocked.toLowerCase())
    );
    
    return { sensitive: isBlocked, blocked: isBlocked };
  }

  // Sanitize and validate the SQL query
  sanitizeAndValidateQuery(sqlQuery, schema) {
    this.blockedColumns = [];
    this.warnings = [];

    const originalColumns = this.extractColumnsFromQuery(sqlQuery);
    const tableName = this.extractTableNameFromQuery(sqlQuery);

    if (!tableName) {
      this.warnings.push({ message: 'Could not determine table name to sanitize columns.' });
      return { sanitizedQuery: sqlQuery, blockedColumns: [], warnings: this.warnings };
    }

    let requestedColumns = originalColumns;
    if (originalColumns.includes('*')) {
      requestedColumns = this.extractSchemaColumnsForTable(schema, tableName);
    }

    const allowedColumns = [];
    for (const column of requestedColumns) {
      const { blocked } = this.isSensitiveColumn(column);
      if (blocked) {
        this.blockedColumns.push({
          column: column,
          category: 'sensitive',
          reason: `Access to '${column}' is blocked.`
        });
      } else {
        allowedColumns.push(column);
      }
    }

    if (this.blockedColumns.length > 0) {
      if (allowedColumns.length === 0) {
        // All requested columns were blocked, return an aggregate
        const firstBlocked = this.blockedColumns[0].column;
        const safeAlternative = safeAlternatives[firstBlocked.toLowerCase()] || `COUNT(*) as record_count`;
        const sanitizedQuery = sqlQuery.replace(/SELECT .*? FROM/i, `SELECT ${safeAlternative} FROM`);
        return { sanitizedQuery, blockedColumns: this.blockedColumns, warnings: this.warnings };
      }
      
      // Rewrite the query with only allowed columns
      const newColumns = allowedColumns.map(c => `\`${c}\``).join(', ');
      const sanitizedQuery = sqlQuery.replace(/SELECT .*? FROM/i, `SELECT ${newColumns} FROM`);
      return { sanitizedQuery, blockedColumns: this.blockedColumns, warnings: this.warnings };
    }

    // Query is safe as is
    return { sanitizedQuery: sqlQuery, blockedColumns: [], warnings: [] };
  }

  // Check individual column
  checkColumn(columnName) {
    const { sensitive, blocked } = this.isSensitiveColumn(columnName);
    
    if (blocked) {
      this.blockedColumns.push({
        column: columnName,
        category: 'sensitive',
        reason: `Access denied: ${columnName} contains sensitive data that cannot be accessed`
      });
    }
  }

  // Extract column names from SQL query
  extractColumnsFromQuery(sqlQuery) {
    const columns = [];
    
    // Match SELECT ... FROM pattern
    const selectMatch = sqlQuery.match(/SELECT\s+(.*?)\s+FROM/i);
    if (selectMatch) {
      const columnsPart = selectMatch[1];
      
      if (columnsPart.includes('*')) {
        columns.push('*');
      } else {
        // Split by comma and clean up
        const cols = columnsPart.split(',').map(col => {
          // Remove aliases, functions, etc.
          const cleaned = col.trim()
            .replace(/\s+as\s+\w+/gi, '')
            .replace(/^\w+\./g, '') // Remove table prefix
            .replace(/[`"'\[\]]/g, ''); // Remove quotes
          
          // Extract column name from functions like COUNT(column)
          const funcMatch = cleaned.match(/\w+\((.*?)\)/);
          if (funcMatch) {
            return funcMatch[1].trim();
          }
          
          return cleaned;
        });
        
        columns.push(...cols);
      }
    }
    
    return columns.filter(col => col && col !== '1' && col !== 'DISTINCT');
  }

  // Extract table name from SQL query
  extractTableNameFromQuery(sqlQuery) {
    const fromMatch = sqlQuery.match(/FROM\s+([`"]?)(\w+)\1/i);
    return fromMatch ? fromMatch[2] : null;
  }

  // Extract columns for a specific table from the schema
  extractSchemaColumnsForTable(schema, tableName) {
    const columns = [];
    const tableRegex = new RegExp(`Table: ${tableName}\\n([\\s\\S]*?)(?:\\n\\n|$)`);
    const tableMatch = schema.match(tableRegex);

    if (tableMatch) {
      const tableSchema = tableMatch[1];
      const lines = tableSchema.split('\n');
      for (const line of lines) {
        const match = line.match(/^\s*-\s+(\w+)\s+\(/);
        if (match) {
          columns.push(match[1]);
        }
      }
    }
    return columns;
  }

  // Generate safe query alternatives
  generateSafeAlternatives(blockedColumns) {
    const alternatives = [];
    
    for (const blocked of blockedColumns) {
      const alternative = safeAlternatives[blocked.column.toLowerCase()];
      if (alternative) {
        alternatives.push({
          original: blocked.column,
          safe: alternative,
          explanation: `Instead of selecting ${blocked.column} directly, use: ${alternative}`
        });
      } else {
        // Generic safe alternative
        alternatives.push({
          original: blocked.column,
          safe: `COUNT(*) as ${blocked.column}_records`,
          explanation: `Use aggregate function instead of accessing ${blocked.column} directly`
        });
      }
    }
    
    return alternatives;
  }

  // Create security report
  createSecurityReport(sqlQuery, validationResult) {
    return {
      timestamp: new Date().toISOString(),
      userRole: this.userRole.description,
      query: sqlQuery,
      allowed: validationResult.allowed,
      blockedColumns: validationResult.blockedColumns,
      warnings: validationResult.warnings,
      reason: validationResult.allowed 
        ? 'Query approved' 
        : `Query blocked due to ${validationResult.blockedColumns.length} sensitive column(s)`
    };
  }
}

module.exports = SecurityValidator;
