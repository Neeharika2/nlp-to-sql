// Metadata catalog for column-level security
const columnSecurity = {
  // All sensitive data types that should be BLOCKED for everyone
  blocked: [
    // Password fields
    'password', 'password_hash', 'hashed_password', 'pwd', 'passwd', 'user_password',
    // PCI data
    'credit_card', 'card_number', 'cvv', 'card_cvv', 'expiry', 'card_expiry', 
    'account_number', 'routing_number', 'bank_account',
    // PII sensitive
    'ssn', 'social_security', 'social_security_number',
    // API credentials
    'api_key', 'secret_key', 'private_key', 'encryption_key',
    // Tokens
    'token', 'access_token', 'refresh_token', 'auth_token'
  ]
};

// Single user role - admin with restrictions
const userRole = {
  level: 100,
  canAccessRegularData: true,    // Can see names, emails, addresses, etc.
  canAccessSensitiveData: false, // Cannot see passwords, credit cards, SSN, etc.
  allowedOperations: ['SELECT'],
  description: 'Admin with access to regular data, sensitive data blocked'
};

// Safe aggregate alternatives for blocked columns
const safeAlternatives = {
  password: 'COUNT(*) as users_with_password',
  password_hash: 'COUNT(*) as users_count',
  hashed_password: 'COUNT(*) as users_count',
  credit_card: 'COUNT(DISTINCT LEFT(credit_card, 4)) as card_types_count',
  card_number: 'COUNT(*) as cards_count',
  cvv: 'COUNT(*) as records_with_cvv',
  ssn: 'COUNT(*) as records_with_ssn',
  social_security: 'COUNT(*) as records_with_ssn',
  api_key: 'COUNT(*) as active_api_keys',
  secret_key: 'COUNT(*) as secret_keys_count',
  token: 'COUNT(*) as active_tokens'
};

module.exports = {
  columnSecurity,
  userRole,
  safeAlternatives
};
