// Copyright 2024 applibrium.com

import {
  getBooleanEnvironmentVariable,
  getIntegerEnvironmentVariable,
  getStringEnvironmentVariable,
} from './env.helper';

describe('envHelper', () => {
  const savedEnv = { ...process.env };

  beforeEach(() => {
    jest.resetAllMocks();
  });
  afterEach(() => {
    process.env = { ...savedEnv };
  });

  describe('getIntegerEnvironmentVariable', () => {
    it.each([
      [undefined, 123, 123],
      ['', 123, 123],
      ['x', 123, 123],
      ['1000', 123, 1000],
    ])(
      'gets environment variable value for %p or default %p',
      (
        envValueMock: undefined | string,
        defaultMock: number,
        expected: number
      ) => {
        process.env.TEST = envValueMock;

        const actualValue = getIntegerEnvironmentVariable('TEST', defaultMock);

        expect(actualValue).toEqual(expected);
      }
    );
  });

  describe('getStringEnvironmentVariable', () => {
    it.each([
      [undefined, undefined, ''],
      [undefined, 'def', 'def'],
      ['', 'def', ''],
      ['x', 'def', 'x'],
    ])(
      'gets environment variable value for %p or default %p',
      (
        envValueMock: undefined | string,
        defaultMock: string | undefined,
        expected: string
      ) => {
        if (defaultMock) {
          process.env.TEST = envValueMock;
        }

        const actualValue = getStringEnvironmentVariable('TEST', defaultMock);

        expect(actualValue).toEqual(expected);
      }
    );
  });

  describe('getBooleanEnvironmentVariable', () => {
    it.each([
      [undefined, undefined, false],
      ['true', undefined, true],
      ['false', undefined, false],
      ['x', undefined, false],
      ['', undefined, false],
      ['', false, false],
      ['', true, true],
    ])(
      'gets environment variable value for %p with default %p',
      (
        envValueMock: undefined | string,
        defaultValue: boolean | undefined,
        expected: boolean
      ) => {
        process.env.TEST = envValueMock;

        const actualValue = getBooleanEnvironmentVariable('TEST', defaultValue);

        expect(actualValue).toEqual(expected);
      }
    );
  });
});
