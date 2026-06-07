export default {
  testRunner: "vitest",
  plugins: ["@stryker-mutator/vitest-runner"],
  mutate: ["src/**/*.ts"],
  reporters: ["html", "progress"],
  htmlReporter: { fileName: "reports/mutation/index.html" },
};
