import { configDefaults, defineConfig } from 'vitest/config'

export default defineConfig({
  test: {
    passWithNoTests: false,
    // CI checks the pinned KithMoot source out here for diff-source; its own
    // tests are not this package's.
    exclude: [...configDefaults.exclude, '.kithmoot-src/**'],
  },
})
