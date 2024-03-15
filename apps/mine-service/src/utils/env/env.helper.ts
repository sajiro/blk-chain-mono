// Copyright 2024 applibrium.com

export const getIntegerEnvironmentVariable = (
  variableKey: string,
  defaultValue: number
): number => {
  const variable = process.env[variableKey];
  return (variable && parseInt(variable)) || defaultValue;
};

export const getStringEnvironmentVariable = (
  variableKey: string,
  defaultValue = ''
): string => {
  const variable = process.env[variableKey];
  return variable ?? defaultValue;
};

export const getBooleanEnvironmentVariable = (
  variableKey: string,
  defaultValue = false
): boolean => {
  const variable = process.env[variableKey];
  return variable === 'true' || defaultValue;
};
