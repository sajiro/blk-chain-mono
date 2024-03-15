import { nxE2EPreset } from '@nx/cypress/plugins/cypress-preset';

import { defineConfig } from 'cypress';

export default defineConfig({
  e2e: {
    ...nxE2EPreset(__filename, {
      cypressDir: 'src',
      bundler: 'vite',
      webServerCommands: {
        default: 'nx run mine-ui:serve',
        production: 'nx run mine-ui:preview',
      },
      ciWebServerCommand: 'nx run mine-ui:serve-static',
    }),
    baseUrl: 'http://localhost:4200',
  },
});
