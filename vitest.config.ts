import { defineConfig, configDefaults } from "vitest/config";

// The root test run covers the library only. The admin console (apps/console)
// is a separate package with its own dependencies and its own `npm test`, so it
// must not be pulled into the library's vitest run — otherwise its
// `@countersignlabs/counter-sign` imports fail on a fresh CI checkout that only
// installs the root dependencies.
export default defineConfig({
  test: {
    exclude: [...configDefaults.exclude, "apps/**"],
  },
});
