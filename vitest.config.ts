import { configDefaults, defineConfig } from 'vitest/config'

export default defineConfig({
  test: {
    passWithNoTests: false,
    // Local pre-push checks share the workstation with other repositories.
    // Keep crypto-heavy tests serial there; CI retains its normal worker pool.
    maxWorkers: process.env.CI ? undefined : 1,
    // CI checks the pinned KithMoot source out here for diff-source; its own
    // tests are not this package's.
    exclude: [...configDefaults.exclude, '.kithmoot-src/**'],
  },
})
