import * as config from "./config.mts"
const fs = await import("fs")
const saml = await import("samlify")
import * as validator from "@authenio/samlify-node-xmllint"
saml.setSchemaValidator(validator)
const express = (await import("express")).default
const spRouter = express.Router()
const app = express()

const spPrivateKey = fs.readFileSync("keys/saml-sp.pem").toString()

const sp = saml.ServiceProvider({
  privateKey: spPrivateKey,  
  ...config.spPublicData
})

const idp = saml.IdentityProvider(config.idpPublicData);

spRouter.get(`/metadata`, 
  (req, res) => res.header("Content-Type", "text/xml").send(sp.getMetadata())
)

spRouter.post(`/assertion`,
  async (req, res) => {
    // console.log(`SAML response:\n${Buffer.from(req.body.SAMLResponse, 'base64').toString('utf-8')}`)
    
    try {
      const loginResponse = await sp.parseLoginResponse(idp, 'post', req);
      res.send(`
        <html>
          <body>
            <h2>Hello ${loginResponse.extract.nameID}</h2>
          </body>
        </html>
      `)
      res.send();
    } catch (err) {
      console.error('Error processing SAML response:', err);
      res.status(400).send('SAML authentication failed');
    }
  }
)

spRouter.get('/login',
  async (req, res) => {
    const loginRequest = await sp.createLoginRequest(idp, "post")
    res.send(`
      <html>
        <body>
          <script>
            window.onload = function () { document.forms[0].submit(); }
          </script>
          
          <form method="post" action="${loginRequest.entityEndpoint}">
            <input type="hidden" name="${loginRequest.type}" value="${loginRequest.context}" />
          </form>
        </body>
      </html>
    `)    
  }
)

app.use(express.urlencoded({extended: true}))
app.use(`/${config.spDir}`, spRouter)

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

app.listen(config.spPort, () => {
  console.log(`service provider is running on http://${config.spHostname}:${config.spPort}`)
})


