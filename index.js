#!/usr/bin/env node
const fs = require('fs')
const express = require('express')
const morgan = require('morgan')
const path = require('path')
require('dotenv').config()

const { configOIDC, configMyInfo, configSGID } = require('./lib/express')

const PORT = process.env.MOCKPASS_PORT || process.env.PORT || 5156

const serviceProvider = {
  cert: fs.readFileSync(
    path.resolve(
      __dirname,
      process.env.SERVICE_PROVIDER_CERT_PATH || './static/certs/client_eckey.json',
    ),
  ),
  pubKey: fs.readFileSync(
    path.resolve(
      __dirname,
      process.env.SERVICE_PROVIDER_PUB_KEY || './static/certs/key.pub',
    ),
  ),
}

const cryptoConfig = {
  signAssertion: process.env.SIGN_ASSERTION !== 'false', // default to true to be backward compatable
  signResponse: process.env.SIGN_RESPONSE !== 'false',
  encryptAssertion: process.env.ENCRYPT_ASSERTION !== 'false',
  resolveArtifactRequestSigned:
    process.env.RESOLVE_ARTIFACT_REQUEST_SIGNED !== 'false',
}

const options = {
  serviceProvider,
  showLoginPage: (req) =>
    (req.header('X-Show-Login-Page') || process.env.SHOW_LOGIN_PAGE) === 'true',
  encryptMyInfo: process.env.ENCRYPT_MYINFO === 'true',
  cryptoConfig,
}

const app = express()
app.use(morgan('combined'))
app.use((...args) => {
  // since UTF-8 and ISO-8859-1 are ASCII-backward-compatible + the assumption that request body
  // doesn't contain non-ASCII character --> we just need to change ISO-8859-1 to UTF-8 without
  // performing addition encoding conversion
  if (args[0].headers['content-type']?.includes('charset=ISO-8859-1')) {
    args[0].headers['content-type'] = args[0].headers['content-type'].replace(
      'charset=ISO-8859-1',
      'charset=UTF-8',
    )
  }
  return express.urlencoded({ extended: false })(...args)
})

configOIDC(app, options)
configSGID(app, options)

configMyInfo.consent(app)
configMyInfo.v3(app, options)

app.enable('trust proxy')
app.use(express.static(path.join(__dirname, 'public')))

app.listen(PORT, '0.0.0.0', (err) =>
  err
    ? console.error('Unable to start MockPass', err)
    : console.warn(`MockPass listening on ${PORT}`),
)
