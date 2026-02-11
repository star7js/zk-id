import js from '@eslint/js';
import tseslint from 'typescript-eslint';
import eslintConfigPrettier from 'eslint-config-prettier';
import globals from 'globals';

export default [
  // Global ignores
  {
    ignores: [
      '**/dist/',
      '**/build/',
      '**/node_modules/',
      '**/coverage/',
      '**/.circom',
      '**/*.sol',
      '**/artifacts/',
      '**/typechain-types/',
      '**/docs/api/',
      'packages/portal/',
    ],
  },

  // Base configs
  js.configs.recommended,
  ...tseslint.configs.recommended,

  // TypeScript source files
  {
    files: [
      'packages/core/src/**/*.ts',
      'packages/sdk/src/**/*.ts',
      'packages/issuer/src/**/*.ts',
      'packages/redis/src/**/*.ts',
      'test/**/*.ts',
    ],
    languageOptions: {
      globals: {
        ...globals.node,
      },
    },
    rules: {
      '@typescript-eslint/no-explicit-any': 'warn',
      '@typescript-eslint/no-unused-vars': [
        'error',
        {
          argsIgnorePattern: '^_',
          varsIgnorePattern: '^_',
        },
      ],
      'no-empty-function': 'off',
      '@typescript-eslint/no-non-null-assertion': 'off',
    },
  },

  // Test files - more lenient
  {
    files: ['test/**/*.ts', '**/*.test.ts', '**/*.spec.ts'],
    rules: {
      '@typescript-eslint/no-explicit-any': 'off',
      '@typescript-eslint/no-unused-expressions': 'off', // Allow chai assertions
      '@typescript-eslint/no-unused-vars': [
        'error',
        {
          argsIgnorePattern: '^_',
          varsIgnorePattern: '^_',
        },
      ],
      '@typescript-eslint/no-require-imports': 'off', // Allow dynamic imports in tests
    },
  },

  // Type definition files - allow any for third-party libraries
  {
    files: ['**/*.d.ts'],
    rules: {
      '@typescript-eslint/no-explicit-any': 'off',
    },
  },

  // Circuit JS tests - CommonJS
  {
    files: ['packages/circuits/test/**/*.js'],
    languageOptions: {
      sourceType: 'commonjs',
      globals: {
        ...globals.node,
        ...globals.mocha,
      },
    },
    rules: {
      '@typescript-eslint/no-require-imports': 'off',
      '@typescript-eslint/no-unused-vars': [
        'error',
        {
          argsIgnorePattern: '^_',
          varsIgnorePattern: '^_',
        },
      ],
    },
  },

  // Prettier must be last to disable conflicting rules
  eslintConfigPrettier,
];
