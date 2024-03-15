// Copyright 2024 applibrium.com

import { SkipAuth } from './skip-auth.decorator';

describe('@SkipAuth', () => {
  const SKIP_AUTH_KEY = 'skipAuth';

  class TestWithMethod {
    @SkipAuth()
    // eslint-disable-next-line @typescript-eslint/no-empty-function
    public static test(): void {}
  }

  it('should enhance method by setting metadata "skipAuth" to true', () => {
    const metadata = Reflect.getMetadata(SKIP_AUTH_KEY, TestWithMethod.test);

    expect(metadata).toBeTrue();
  });
});
