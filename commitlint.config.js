module.exports = {
  extends: ['@commitlint/config-conventional'],
  rules: {
    'subject-case': [2, 'never', ['start-case', 'pascal-case', 'upper-case']],
    'scope-case': [2, 'always', ['pascal-case', 'lower-case', 'camel-case']],
    'footer-max-line-length': [0],
    'subject-empty': [0],
    'type-empty': [0],
    'subject-full-stop': [0],
    'body-leading-blank': [0],
    'footer-leading-blank': [0],
  },
}
