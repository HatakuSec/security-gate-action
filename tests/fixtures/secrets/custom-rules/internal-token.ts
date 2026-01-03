// Test file for custom rule detection

// This should match a custom rule for internal tokens
const _internalToken = 'INT_TOKEN_ABC123XYZ789';

// This should also match
export const anotherToken = 'INT_TOKEN_SECRETVALUE01';

// This should NOT match (wrong prefix)
const _otherValue = 'EXT_TOKEN_ABC123XYZ789';
