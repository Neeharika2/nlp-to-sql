# NLP to SQL Query Interface

A modern web application that converts natural language queries into SQL using AI, with interactive data visualization and multi-database support.

## Features

### 🤖 Natural Language to SQL
- Convert plain English questions into SQL queries using Google Gemini AI
- Intelligent query understanding and context-aware SQL generation
- Support for complex queries including joins, aggregations, and filters

### 📊 Interactive Data Visualization
- **Smart Chart Suggestions**: AI-powered chart type recommendations based on query results
- **Multiple Chart Types**: Bar, Line, Pie, Doughnut, and Scatter plots
- **Auto-Configuration**: Automatic X/Y axis selection based on data types
- **Real-time Updates**: Charts update instantly when changing visualization options
- **Export Capabilities**: Download charts as PNG images


### 🎯 User-Friendly Interface
- **Tab-Based Layout**: Separate views for Table Data, Charts, and SQL Query
- **Collapsible Sidebar**: Database schema explorer with table and column information
- **Query History**: Track and reuse recent queries
- **Saved Queries**: Bookmark frequently used queries
- **Suggested Queries**: Quick access to common query patterns

### 🔐 Authentication
- Google OAuth integration
- Secure session management
- User profile management

### 📈 Data Management
- **Export Options**: CSV and Excel export for query results
- **Table Search**: Filter results in real-time
- **Column Sorting**: Sort by any column with a single click
- **Responsive Tables**: Optimized scrolling for large datasets

## Installation

### Prerequisites
- Node.js (v14 or higher)
- npm or yarn
- Database server (MySQL, PostgreSQL, etc.)
- Google Cloud Platform account (for OAuth and Gemini API)

### Setup

1. **Clone the repository**
   ```bash
   git clone https://github.com/Neeharika2/nlp-to-sql.git
   cd nlp-to-sql
   ```

2. **Install dependencies**
   ```bash
   npm install
   ```

3. **Configure environment variables**
   
   Create a `.env` file in the root directory:
   ```env
   # Server Configuration
   PORT=3000
   SESSION_SECRET=your-secret-key-here

   # Google OAuth
   GOOGLE_CLIENT_ID=your-google-client-id
   GOOGLE_CLIENT_SECRET=your-google-client-secret
   GOOGLE_CALLBACK_URL=http://localhost:3000/auth/google/callback

   # Google Gemini AI API
   GEMINI_API_KEY=your-gemini-api-key

   # Database Configuration (example for MySQL)
   DB_TYPE=mysql
   DB_HOST=localhost
   DB_PORT=3306
   DB_USER=your-database-user
   DB_PASSWORD=your-database-password
   DB_NAME=your-database-name
   ```

4. **Set up Google Cloud Platform**
   - Create a project in [Google Cloud Console](https://console.cloud.google.com/)
   - Enable Google+ API
   - Create OAuth 2.0 credentials
   - Enable Gemini API and get API key

5. **Start the application**
   ```bash
   npm start
   ```

   For development with auto-reload:
   ```bash
   npm run dev
   ```

6. **Access the application**
   
   Open your browser and navigate to `http://localhost:3000`

## Usage

### Basic Workflow

1. **Login**: Authenticate using your Google account

2. **Select Database**: Choose your target database from the dropdown

3. **Ask Questions**: Type natural language queries like:
   - "Show all customers from New York"
   - "What are the top 5 products by sales?"
   - "Count orders by month for the last year"

4. **View Results**: 
   - **Table View**: See query results in an interactive table
   - **Chart View**: Visualize data with auto-suggested chart types
   - **SQL Query**: Review the generated SQL code

5. **Interact with Data**:
   - Search and filter table results
   - Sort by any column
   - Export to CSV or Excel
   - Create custom visualizations

6. **Save & Reuse**:
   - Bookmark useful queries
   - Access query history
   - Share results with team members

### Chart Functionality

The chart system automatically:
- Analyzes your query results
- Suggests the most appropriate chart type
- Selects optimal X and Y axes
- Renders interactive visualizations

You can customize:
- Chart type (Bar, Line, Pie, Doughnut, Scatter)
- X and Y axis columns
- Chart title and labels
- Color themes
- Animation settings

## Project Structure

```
nlptosql/
├── config/
│   ├── passport-setup.js      # OAuth configuration
│   └── security-config.js     # Security settings
├── models/
│   └── query-history.js       # Query history management
├── routes/
│   ├── auth-routes.js         # Authentication routes
│   ├── database-routes.js     # Database connection routes
│   └── query-routes.js        # Query execution routes
├── utils/
│   ├── audit-logger.js        # Logging utilities
│   └── security-validator.js  # Input validation
├── views/
│   ├── database-config.ejs    # Database configuration page
│   ├── database-select.ejs    # Database selection page
│   ├── home.ejs               # Landing page
│   ├── login.ejs              # Login page
│   ├── profile.ejs            # User profile page
│   └── query-interface.ejs    # Main query interface
├── logs/                      # Application logs
├── .env                       # Environment variables
├── app.js                     # Main application file
└── package.json               # Dependencies
```

## Technologies Used

### Backend
- **Node.js** - Runtime environment
- **Express.js** - Web framework
- **Passport.js** - Authentication middleware
- **Google Gemini AI** - Natural language processing

### Frontend
- **EJS** - Templating engine
- **Chart.js** - Data visualization
- **Font Awesome** - Icons
- **html2canvas** - Chart export to PNG
- **jsPDF** - PDF generation

### Database Drivers
- **mysql2** - MySQL
- **pg** - PostgreSQL
- **tedious** - MS SQL Server
- **mongodb** - MongoDB
- **@supabase/supabase-js** - Supabase

## Security Features

- Input validation and sanitization
- SQL injection prevention
- Session-based authentication
- CORS protection
- Environment variable management
- Audit logging

## API Endpoints

### Authentication
- `GET /auth/google` - Initiate Google OAuth
- `GET /auth/google/callback` - OAuth callback
- `GET /auth/logout` - Logout user

### Database
- `GET /database/select` - Database selection page
- `POST /database/connect` - Connect to database
- `GET /database/config` - Database configuration

### Queries
- `POST /query/execute` - Execute natural language query
- `GET /query/history` - Get query history
- `GET /query/saved` - Get saved queries
- `POST /query/save` - Save a query
- `DELETE /query/saved/:id` - Delete saved query
- `GET /query/schema` - Get database schema

## Contributing

Contributions are welcome! Please follow these steps:

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

## License

This project is licensed under the MIT License.

## Support

For issues, questions, or suggestions:
- Open an issue on [GitHub](https://github.com/Neeharika2/nlp-to-sql/issues)
- Contact: [Your Email]

## Acknowledgments

- Google Gemini AI for natural language processing
- Chart.js for data visualization
- All contributors and open-source libraries used in this project

---

