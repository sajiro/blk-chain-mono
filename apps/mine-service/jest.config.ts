/* eslint-disable */
export default {
  displayName: 'mine-service',
  preset: '../../jest.preset.js',
  testEnvironment: 'node',
  transform: {
    '^.+\\.[tj]s$': ['ts-jest', { tsconfig: '<rootDir>/tsconfig.spec.json' }],
  },
  moduleFileExtensions: ['ts', 'js', 'html'],
  coverageDirectory: '../../coverage/apps/mine-service',
  coverageReporters: ['text'],
  coverageThreshold: {
    global: {
      statements: 95,
      branches: 85,
      functions: 95,
      lines: 95,
    },
  },
  setupFilesAfterEnv: ['jest-extended/all'],
};
