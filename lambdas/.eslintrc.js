module.exports = {
    parser: "@typescript-eslint/parser",
    parserOptions: {
        ecmaVersion: 2022, // Allows for the parsing of modern ECMAScript features
        sourceType: "module",
    },
    env: {
        node: true,
        es2022: true,
        jest: true,
    },
    globals: {
        sinon: true,
        expect: true,
    },
    root: true,
    extends: ["eslint:recommended", "prettier", "plugin:@typescript-eslint/recommended"],
    rules: {
        "no-console": 2,
        "padding-line-between-statements": ["error", { blankLine: "any", prev: "*", next: "*" }],
        "@typescript-eslint/no-unused-vars": ["error", { varsIgnorePattern: "^_", argsIgnorePattern: "^_" }],
    },
};
