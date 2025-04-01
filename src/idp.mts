import * as config from "./config.mts"
const fs = await import("fs")
const saml = await import("samlify")
import * as validator from "@authenio/samlify-xsd-schema-validator"
saml.setSchemaValidator(validator)
const express = (await import("express")).default
const app = express()
const xmlParser = new (await import("fast-xml-parser")).XMLParser(
  {
    ignoreAttributes: false, // Preserve attributes
    attributeNamePrefix: "@_", // Prefix for attributes
  }
)

const idpPrivateKey = fs.readFileSync("keys/saml-idp.pem").toString()

const idp = saml.IdentityProvider({
  privateKey: idpPrivateKey,  
  ...config.idpPublicData
})

const sp = saml.ServiceProvider(config.spPublicData)

const getLoginPage = requestId => `
<html>
  <head>
    <title>Login page</title>
  </head>
  <body>
    <h2>Login page</h2>
    <form method="post" action="./loginSubmitted">
      <input type="hidden" name="requestId" value="${requestId}" />
      Email address: <input name="email" />
      <br />
      <button type="Submit">
        Login to the service provider
      </button>
    </form>
  </body>
</html>
`

const idpRouter = express.Router()

idpRouter.post("/loginSubmitted", async (req, res) => {
  const loginResponse = await idp.createLoginResponse(
    sp, 
    {
      authnContextClassRef: 'urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport',
      audience: sp.entityID,
      extract: {
        request: {
          id: req.body.requestId
        }
      },
      signingKey: { privateKey: idpPrivateKey, publicKey: config.idpCert }  // Ensure signing
    },
    "post",
    {
      email: req.body.email
    }
  );

  // const samlResponseDecoded = Buffer.from(loginResponse.context, "base64").toString("utf8");
  // console.log("Decoded SAML Response:", samlResponseDecoded);

  res.send(`
    <html>
      <body>
        <script>
          window.onload = function () { document.forms[0].submit(); }
        </script>
        
        <form method="post" action="${loginResponse.entityEndpoint}">
          <input type="hidden" name="${loginResponse.type}" value="${loginResponse.context}" />
        </form>
      </body>
    </html>
  `)

})

// IdP endpoint for login requests
idpRouter.post(`/login`,
  async (req, res) => {
    try {
      // Workaround because I couldn't get parseLoginRequest to work.
      // const loginRequest = await idp.parseLoginRequest(sp, 'post', req)
      const samlRequest = xmlParser.parse(Buffer.from(req.body.SAMLRequest, 'base64').toString('utf-8'))
      res.send(getLoginPage(samlRequest["samlp:AuthnRequest"]["@_ID"]))
    } catch (err) {
      console.error('Error processing SAML response:', err);
      res.status(400).send('SAML authentication failed');
    }
  }
)

idpRouter.get(`/metadata`, 
  (req, res) => res.header("Content-Type", "text/xml").send(idp.getMetadata())
)

app.use(express.urlencoded({extended: true}))
app.use(`/${config.idpDir}`, idpRouter)

app.get("/", (req, res) => {
  res.send(`
    <html>
      <body>
        <button onClick="document.location.href='${config.spUrl}/login'">
           Click here to log on
        </button>
      </body>
    </html>
  `)
})

app.listen(config.idpPort, () => {
  console.log(`identity provider is running on http://${config.idpHostname}:${config.idpPort}`)
})