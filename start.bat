REM Some familiarity with SAML Artifact Binding is assumed
REM Optional: Configure where MockPass should send SAML artifact to, default endpoint will be `PartnerId` in request query parameter.
set SINGPASS_ASSERT_ENDPOINT=http://localhost:5000/singpass/assert
set CORPPASS_ASSERT_ENDPOINT=http://localhost:5000/corppass/assert

REM All values shown here are defaults
set MOCKPASS_PORT=5156
set MOCKPASS_NRIC=S8979373D
set MOCKPASS_UEN=123456789A

set SHOW_LOGIN_PAGE=true
REM Optional, defaults to `false`

REM Disable signing/encryption (Optional, by default `true`)
set SIGN_ASSERTION=false
set ENCRYPT_ASSERTION=false
set SIGN_RESPONSE=false
set RESOLVE_ARTIFACT_REQUEST_SIGNED=false

REM Encrypt payloads returned by /myinfo/*/{person, person-basic},
REM equivalent to MyInfo Auth Level L2 (testing and production)
set ENCRYPT_MYINFO=false

REM If specified, will verify token provided in Authorization header
REM for requests to /myinfo/*/token
set SERVICE_PROVIDER_MYINFO_SECRET=myinfosecret

npm start
