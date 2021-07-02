#!/bin/bash

# Some familiarity with SAML Artifact Binding is assumed
# Optional: Configure where MockPass should send SAML artifact to, default endpoint will be `PartnerId` in request query parameter.
export SINGPASS_ASSERT_ENDPOINT=http://localhost:5000/singpass/assert
export CORPPASS_ASSERT_ENDPOINT=http://localhost:5000/corppass/assert

# All values shown here are defaults
export MOCKPASS_PORT=5156
export MOCKPASS_NRIC=S8979373D
export MOCKPASS_UEN=123456789A

export SHOW_LOGIN_PAGE=true
# Optional, defaults to `false`

# Disable signing/encryption (Optional, by default `true`)
export SIGN_ASSERTION=false
export ENCRYPT_ASSERTION=false
export SIGN_RESPONSE=false
export RESOLVE_ARTIFACT_REQUEST_SIGNED=false

# Encrypt payloads returned by /myinfo/*/{person, person-basic},
# equivalent to MyInfo Auth Level L2 (testing and production)
export ENCRYPT_MYINFO=false

# If specified, will verify token provided in Authorization header
# for requests to /myinfo/*/token
export SERVICE_PROVIDER_MYINFO_SECRET=myinfosecret

npm start
