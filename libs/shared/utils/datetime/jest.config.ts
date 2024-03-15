/* eslint-disable */
export default {
  displayName: 'shared-utils-datetime',
  preset: '../../../../jest.preset.js',
  transform: {
    '^.+\\.[tj]s$': ['ts-jest', { tsconfig: '<rootDir>/tsconfig.spec.json' }],
  },
  moduleFileExtensions: ['ts', 'js', 'html'],
  coverageDirectory: '../../../../coverage/libs/shared/utils/datetime',
  coverageReporters: ['text'],
  coverageThreshold: {
    global: {
      statements: 95,
      branches: 85,
      functions: 95,
      lines: 95,
    },
  },
};
