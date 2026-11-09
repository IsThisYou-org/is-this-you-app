module.exports = {
  preset: '@react-native/jest-preset',
  testMatch: [
    '<rootDir>/__tests__/**/*.test.ts',
    '<rootDir>/__tests__/**/*.test.tsx',
    '<rootDir>/packages/*/test/**/*.test.ts',
  ],
  moduleNameMapper: {
    '^@isthisyou/dnssec-zone$': '<rootDir>/packages/dnssec-zone/src/index.ts',
    '^@isthisyou/keystore$': '<rootDir>/packages/keystore/src/index.ts',
    '^@isthisyou/keystore/react-native$': '<rootDir>/packages/keystore/src/react-native.ts',
  },
};
