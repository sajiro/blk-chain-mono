// Copyright 2024 applibrium.com

import dayjs from 'dayjs';
import {
  getNewDate,
  getDateForWeekday,
  convertMinutesToHours,
  convertHoursToMinutes,
  formatEventTime,
  roundEventTime,
  formatMinutesAsTime,
  parseEventTimeString,
  convertTimeInputString,
  isoDateStringToLocalDate,
  dateToISODateString,
} from './datetime.helper';

describe('datetimeHelper', () => {
  beforeEach(() => {
    jest.restoreAllMocks();
  });

  describe('getNewDate', () => {
    const datetimeString = '2019-05-14T11:01:58.135Z';
    const datetimeMock = new Date(datetimeString);

    it('returns current date', () => {
      // Adapted from https://codewithhugo.com/mocking-the-current-date-in-jest-tests/
      jest.spyOn(global, 'Date').mockImplementationOnce(() => datetimeMock);

      expect(getNewDate()).toEqual(datetimeMock);
    });
  });

  describe('getDateForWeekday', () => {
    const testMonday = new Date('2023-08-07');
    const testWednesday = new Date('2023-08-09');
    const testSunday = new Date('2023-08-13');

    const today = getNewDate();
    const hoursOffset = today.getUTCHours() - today.getHours();

    testMonday.setUTCHours(hoursOffset);
    testWednesday.setUTCHours(hoursOffset);
    testSunday.setUTCHours(hoursOffset);

    it.each([
      [1, 'Monday', testMonday, testMonday],
      [1, 'Wednesday', testWednesday, testMonday],
      [1, 'Sunday', testSunday, testMonday],
      [3, 'Monday', testMonday, testWednesday],
      [3, 'Wednesday', testWednesday, testWednesday],
      [3, 'Sunday', testSunday, testWednesday],
      [7, 'Monday', testMonday, testSunday],
      [7, 'Wednesday', testWednesday, testSunday],
      [7, 'Sunday', testSunday, testSunday],
    ])(
      'returns day %i of the week containing input weekday %s',
      (
        weekdayNum: number,
        inputDateString: string,
        inputDate: Date,
        expectedDate: Date
      ) => {
        const dayOfWeekLocal = getDateForWeekday(weekdayNum, inputDate);

        const dayOfWeekUTC = dayjs(dayOfWeekLocal).toDate();
        const expectedDay = dayjs(expectedDate).toDate();

        expect(dayOfWeekUTC).toEqual(expectedDay);
      }
    );
  });

  describe('convertMinutesToHours', () => {
    it('converts minutes to hours', () => {
      const minutes = 150;
      const expectedHours = 2.5;

      const result = convertMinutesToHours(minutes);

      expect(result).toBe(expectedHours);
    });
  });

  describe('convertHoursToMinutes', () => {
    it('converts hours to minutes', () => {
      const hours = 3;
      const expectedMinutes = 180;

      const result = convertHoursToMinutes(hours);

      expect(result).toBe(expectedMinutes);
    });
  });

  describe('convertTimeInputString', () => {
    it.each([
      ['-1', 0],
      ['0', 0],
      ['1', 1],
      ['24', 24],
      ['25', 24],
      ['1.1', 1.1],
      ['1.25', 1.25],
      ['1.14', 1.13],
      ['1:00', 1],
      ['1:06', 1.1],
      ['1:15', 1.25],
      ['1:20', 1.33],
    ])(
      'parse event time string %s to number %d',
      (timeString: string, expected: number) => {
        const result = convertTimeInputString(timeString);

        expect(result).toBe(expected);
      }
    );
  });

  describe('parseEventTimeString', () => {
    it('throws error if timeString does not contain the colon character', () => {
      const timeString = '12.34';
      const expectedError = new Error(
        `An error occurred: timeString '${timeString}' is missing a colon`
      );

      expect(() => {
        parseEventTimeString(timeString);
      }).toThrow(expectedError);
    });

    it.each([
      ['1:00', 1],
      ['1:06', 1.1],
      ['1:15', 1.25],
      ['12:6', 12.1],
    ])(
      'parse event time string %s to number %d',
      (timeString: string, expected: number) => {
        const result = parseEventTimeString(timeString);

        expect(result).toBe(expected);
      }
    );
  });

  describe('roundEventTime', () => {
    it.each([
      [1.234, 1.23],
      [1.678, 1.68],
    ])('round event time %d hours to %d', (hours: number, expected: number) => {
      const result = roundEventTime(hours);

      expect(result).toBe(expected);
    });
  });

  describe('formatEventTime', () => {
    it.each([
      [0, '0:00'],
      [3, '3:00'],
      [4.5, '4:30'],
      [11, '11:00'],
      [12.8, '12:48'],
    ])(
      'returns event time %s in hh:mm format',
      (inputTime: number, outputString: string) => {
        const result = formatEventTime(inputTime);

        expect(result).toEqual(outputString);
      }
    );
  });

  describe('formatMinutesAsTime', () => {
    it.each([
      [0, '0:00'],
      [1, '0:01'],
      [10, '0:10'],
      [59, '0:59'],
      [60, '1:00'],
      [61, '1:01'],
    ])(
      'formats minutes %p to time',
      (minutesMock: number, expectedTime: string) => {
        expect(formatMinutesAsTime(minutesMock)).toEqual(expectedTime);
      }
    );
  });

  describe('isoDateStringToLocalDate', () => {
    it('converts ISO date string to local Date', () => {
      expect(isoDateStringToLocalDate('2023-09-07')).toEqual(
        new Date(2023, 8, 7)
      );
    });
  });

  describe('dateToISODateString', () => {
    it('convert Date instance to ISO date string', () => {
      const isoDateStringMock = '2023-09-07';
      const dateMock = isoDateStringToLocalDate(isoDateStringMock);

      expect(dateToISODateString(dateMock)).toEqual(isoDateStringMock);
    });
  });
});
