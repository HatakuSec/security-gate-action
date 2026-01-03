/** @type {import('eslint').Linter.LegacyConfig} */
module.exports = {
  root: true,
  env: {
    node: true,
    es2022: true,
  },
  parser: '@typescript-eslint/parser',
  parserOptions: {
    ecmaVersion: 2022,
    sourceType: 'module',
    project: './tsconfig.json',
  },
  plugins: ['@typescript-eslint', 'prettier'],
  extends: [
    'eslint:recommended',
    'plugin:@typescript-eslint/recommended',
    'plugin:@typescript-eslint/recommended-requiring-type-checking',
    'plugin:prettier/recommended',
  ],
  rules: {
    // TypeScript-specific rules
    '@typescript-eslint/explicit-function-return-type': 'warn',
    '@typescript-eslint/no-unused-vars': [
      'error',
      { argsIgnorePattern: '^_', varsIgnorePattern: '^_' },
    ],
    '@typescript-eslint/no-explicit-any': 'warn',
    '@typescript-eslint/prefer-nullish-coalescing': 'error',
    '@typescript-eslint/prefer-optional-chain': 'error',
    '@typescript-eslint/strict-boolean-expressions': 'off',

    // General rules
    'no-console': 'warn',
    'no-debugger': 'error',
    eqeqeq: ['error', 'always'],
    curly: ['error', 'all'],

    // Prettier integration
    'prettier/prettier': 'error',
  },
  ignorePatterns: ['dist/', 'node_modules/', 'coverage/', 'scripts/*.mjs'],
  overrides: [
    {
      files: ['tests/**/*.ts'],
      parserOptions: {
        project: './tsconfig.test.json',
      },
      rules: {
        // Relaxed rules for tests
        '@typescript-eslint/no-explicit-any': 'off',
        '@typescript-eslint/no-unsafe-assignment': 'off',
        '@typescript-eslint/no-unsafe-member-access': 'off',
        '@typescript-eslint/no-unsafe-call': 'off',
        'no-console': 'off',
      },
    },
  ],
};
