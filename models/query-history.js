// In-memory storage for query history and saved queries
// In production, use a proper database like MongoDB or PostgreSQL

class QueryHistoryManager {
  constructor() {
    // Store query history per user
    this.queryHistory = new Map(); // userId -> array of queries
    this.savedQueries = new Map(); // userId -> array of saved queries
    this.savedCharts = new Map(); // userId -> array of saved charts
  }

  // Add query to history
  addToHistory(userId, queryData) {
    if (!this.queryHistory.has(userId)) {
      this.queryHistory.set(userId, []);
    }

    const history = this.queryHistory.get(userId);
    
    const entry = {
      id: Date.now().toString(),
      nlQuery: queryData.nlQuery,
      sqlQuery: queryData.sqlQuery,
      database: queryData.database,
      dbType: queryData.dbType,
      timestamp: new Date().toISOString(),
      success: queryData.success,
      rowsReturned: queryData.rowsReturned || 0
    };

    // Keep only last 50 queries
    history.unshift(entry);
    if (history.length > 50) {
      history.pop();
    }

    this.queryHistory.set(userId, history);
    return entry;
  }

  // Get user's query history
  getHistory(userId, limit = 20) {
    if (!this.queryHistory.has(userId)) {
      return [];
    }
    return this.queryHistory.get(userId).slice(0, limit);
  }

  // Save a query with custom name
  saveQuery(userId, queryData) {
    if (!this.savedQueries.has(userId)) {
      this.savedQueries.set(userId, []);
    }

    const saved = this.savedQueries.get(userId);
    
    const entry = {
      id: Date.now().toString() + '-' + Math.random().toString(36).substr(2, 9),
      name: queryData.name || 'Untitled Query',
      nlQuery: queryData.nlQuery,
      sqlQuery: queryData.sqlQuery,
      database: queryData.database,
      dbType: queryData.dbType,
      timestamp: new Date().toISOString(),
      tags: queryData.tags || []
    };

    saved.unshift(entry);
    this.savedQueries.set(userId, saved);
    return entry;
  }

  // Get saved queries
  getSavedQueries(userId) {
    if (!this.savedQueries.has(userId)) {
      return [];
    }
    return this.savedQueries.get(userId);
  }

  // Delete saved query
  deleteSavedQuery(userId, queryId) {
    if (!this.savedQueries.has(userId)) {
      return false;
    }

    const saved = this.savedQueries.get(userId);
    const index = saved.findIndex(q => q.id === queryId);
    
    if (index !== -1) {
      saved.splice(index, 1);
      this.savedQueries.set(userId, saved);
      return true;
    }
    
    return false;
  }

  // Update saved query name
  updateQueryName(userId, queryId, newName) {
    if (!this.savedQueries.has(userId)) {
      return false;
    }

    const saved = this.savedQueries.get(userId);
    const query = saved.find(q => q.id === queryId);
    
    if (query) {
      query.name = newName;
      this.savedQueries.set(userId, saved);
      return true;
    }
    
    return false;
  }

  // Get query by ID
  getQueryById(userId, queryId) {
    if (!this.savedQueries.has(userId)) {
      return null;
    }

    const saved = this.savedQueries.get(userId);
    return saved.find(q => q.id === queryId) || null;
  }

  // Save chart configuration
  saveChart(userId, chartData) {
    if (!this.savedCharts.has(userId)) {
      this.savedCharts.set(userId, []);
    }

    const charts = this.savedCharts.get(userId);
    
    const entry = {
      id: Date.now().toString() + '-chart-' + Math.random().toString(36).substr(2, 9),
      name: chartData.name || 'Untitled Chart',
      config: chartData.config,
      database: chartData.database,
      dbType: chartData.dbType,
      timestamp: new Date().toISOString()
    };

    charts.unshift(entry);
    this.savedCharts.set(userId, charts);
    return entry;
  }

  // Get saved charts
  getSavedCharts(userId) {
    if (!this.savedCharts.has(userId)) {
      return [];
    }
    return this.savedCharts.get(userId);
  }

  // Delete saved chart
  deleteSavedChart(userId, chartId) {
    if (!this.savedCharts.has(userId)) {
      return false;
    }

    const charts = this.savedCharts.get(userId);
    const index = charts.findIndex(c => c.id === chartId);
    
    if (index !== -1) {
      charts.splice(index, 1);
      this.savedCharts.set(userId, charts);
      return true;
    }
    
    return false;
  }
}

module.exports = new QueryHistoryManager();
