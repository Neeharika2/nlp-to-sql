const fs = require('fs').promises;
const path = require('path');

class AuditLogger {
  constructor(logDir = path.join(__dirname, '../logs')) {
    this.logDir = logDir;
    this.ensureLogDir();
  }

  async ensureLogDir() {
    try {
      await fs.mkdir(this.logDir, { recursive: true });
    } catch (error) {
      console.error('Error creating log directory:', error);
    }
  }

  // Log query attempt
  async logQueryAttempt(logEntry) {
    const timestamp = new Date().toISOString();
    const date = timestamp.split('T')[0];
    const logFile = path.join(this.logDir, `audit-${date}.log`);
    
    const entry = {
      timestamp,
      userId: logEntry.userId,
      userEmail: logEntry.userEmail,
      userRole: logEntry.userRole,
      database: logEntry.database,
      dbType: logEntry.dbType,
      naturalLanguageQuery: logEntry.nlQuery,
      generatedSQL: logEntry.sqlQuery,
      status: logEntry.status, // 'allowed', 'blocked', 'error'
      blockedColumns: logEntry.blockedColumns || [],
      warnings: logEntry.warnings || [],
      reason: logEntry.reason,
      executionTime: logEntry.executionTime,
      rowsReturned: logEntry.rowsReturned,
      error: logEntry.error
    };

    try {
      await fs.appendFile(
        logFile,
        JSON.stringify(entry) + '\n',
        'utf8'
      );
      
      // Also log to console in development
      if (process.env.NODE_ENV !== 'production') {
        console.log('Audit Log:', entry);
      }
    } catch (error) {
      console.error('Error writing audit log:', error);
    }
  }

  // Log security violation
  async logSecurityViolation(violation) {
    const timestamp = new Date().toISOString();
    const date = timestamp.split('T')[0];
    const logFile = path.join(this.logDir, `security-violations-${date}.log`);
    
    const entry = {
      timestamp,
      severity: 'HIGH',
      userId: violation.userId,
      userEmail: violation.userEmail,
      attemptedQuery: violation.query,
      blockedColumns: violation.blockedColumns,
      reason: violation.reason
    };

    try {
      await fs.appendFile(
        logFile,
        JSON.stringify(entry) + '\n',
        'utf8'
      );
      
      console.warn('SECURITY VIOLATION:', entry);
    } catch (error) {
      console.error('Error writing security violation log:', error);
    }
  }

  // Get audit logs for a user
  async getUserAuditLogs(userId, limit = 100) {
    try {
      const files = await fs.readdir(this.logDir);
      const auditFiles = files
        .filter(f => f.startsWith('audit-'))
        .sort()
        .reverse()
        .slice(0, 7); // Last 7 days
      
      const logs = [];
      
      for (const file of auditFiles) {
        const content = await fs.readFile(path.join(this.logDir, file), 'utf8');
        const lines = content.split('\n').filter(line => line.trim());
        
        for (const line of lines) {
          try {
            const entry = JSON.parse(line);
            if (entry.userId === userId) {
              logs.push(entry);
            }
          } catch (e) {
            // Skip malformed lines
          }
        }
        
        if (logs.length >= limit) break;
      }
      
      return logs.slice(0, limit);
    } catch (error) {
      console.error('Error reading audit logs:', error);
      return [];
    }
  }
}

module.exports = new AuditLogger();
