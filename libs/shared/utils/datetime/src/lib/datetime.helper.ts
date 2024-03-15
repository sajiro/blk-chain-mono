// Copyright 2024 applibrium.com

import dayjs from 'dayjs';

export const weekdayStrings = [
  'monday',
  'tuesday',
  'wednesday',
  'thursday',
  'friday',
  'saturday',
  'sunday',
];

export const getNewDate = (): Date => new Date();

/**************
 * Get the date of a weekday (Monday = 1 ... Sunday = 7)
 * in a given week, which is the Monday-to-Sunday containing refDate
 */
export const getDateForWeekday = (
  weekday: number | string,
  refDate: Date
): Date => {
  const refDay = dayjs(refDate);

  const startSunday =
    refDay.day() === 0 ? refDay.subtract(7, 'day') : refDay.startOf('week');

  const dateDiff =
    typeof weekday === 'number' ? weekday : weekdayStrings.indexOf(weekday) + 1;

  const thisDay = startSunday.add(dateDiff, 'day');
  const thisDate = thisDay.toDate();

  return thisDate;
};

// convert minutes (integers) to hours (2-decimal)
export const convertMinutesToHours = (minutes: number): number => {
  const hours = minutes / 60;
  const roundedHours = Math.round(hours * 100) / 100;

  return roundedHours;
};

// convert hours (2-decimal) to minutes (integers)
export const convertHoursToMinutes = (hours: number): number => {
  const hours24 = Math.min(Math.max(hours, 0), 24);
  const minutes = Math.round(hours24 * 60);

  return minutes;
};

export const timeInputRegex = /^[0-9]{0,2}([.:][0-9]{0,2})?$/;

export const convertTimeInputString = (inputString: string): number => {
  let value = 0;

  if (inputString) {
    const inputValue = inputString.includes(':')
      ? parseEventTimeString(inputString)
      : Number.parseFloat(inputString);

    if (inputValue < 0) {
      value = 0;
    } else if (inputValue > 24) {
      value = 24;
    } else {
      value = roundEventTime(inputValue);
    }
  }

  return value;
};

// parse event time from 'hh:mm' string to decimal number
export const parseEventTimeString = (timeString: string): number => {
  if (!timeString.includes(':')) {
    throw new Error(
      `An error occurred: timeString '${timeString}' is missing a colon`
    );
  }

  const timeArray = timeString.split(':');
  const firstString = timeArray[0] || '0';
  const secondString = timeArray[1] || '0';

  const hours = Number.parseInt(firstString);
  const minutes = Number.parseInt(secondString);
  const eventTime = hours + convertMinutesToHours(minutes);

  return eventTime;
};

/**************
  In some cases, converting hours (2-decimal) to minutes (integers)
  then back to hours results in a different number. 
    eg: 0.14 hours => 8 minutes => 0.13 hour
  
  This is the inevitable result of our event time rounding rules.

  We use the roundEventTime() function below to adjust the number right after
  the user enters event time (hours) in WorkInput and EventTypePopover,
  so that they know what's happening. 
*/
export const roundEventTime = (hours: number): number => {
  const minutes = convertHoursToMinutes(hours);
  const result = convertMinutesToHours(minutes);

  return result;
};

export const formatEventTime = (eventHours: number): string => {
  const hours = Math.floor(eventHours);

  const minutes = Math.round((eventHours - hours) * 60);
  const minutesString = minutes < 10 ? `0${minutes}` : `${minutes}`;

  return `${hours}:${minutesString}`;
};

export const formatMinutesAsTime = (minutes: number): string => {
  const hours = Math.floor(minutes / 60);
  const remainingMinutes = minutes % 60;

  return `${hours}:${
    remainingMinutes < 10 ? `0${remainingMinutes}` : remainingMinutes
  }`;
};

export const isoDateStringToLocalDate = (isoDateString: string): Date =>
  new Date(`${isoDateString}T00:00:00`);

export const dateToISODateString = (date: Date): string =>
  date.toISOString().split('T')[0];
