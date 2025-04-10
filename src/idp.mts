import * as config from "./config.mts"
const fs = await import("fs")
const saml = await import("samlify")
import * as validator from "@authenio/samlify-node-xmllint"
saml.setSchemaValidator(validator)
const express = (await import("express")).default
const app = express()
const xmlParser = new (await import("fast-xml-parser")).XMLParser(
  {
    ignoreAttributes: false, // Preserve attributes
    attributeNamePrefix: "@_", // Prefix for attributes
  }
)
import { v4 as uuidv4 } from 'uuid'
import { verifyMessage } from 'viem'


const loginPrompt = "To access the service provider, sign this nonce: "

const idpPrivateKey = fs.readFileSync("keys/saml-idp.pem").toString()

const idp = saml.IdentityProvider({
  privateKey: idpPrivateKey,  
  ...config.idpPublicData
})

const sp = saml.ServiceProvider(config.spPublicData)

// Keep requestIDs here
let nonces = {}

const getSignaturePage = requestId => {
  const nonce = uuidv4()
  nonces[nonce] = requestId

  return `
<html>
  <head>
    <script type="module">
      import { createWalletClient, custom, getAddress } from 'https://esm.sh/viem'
      if (!window.ethereum) {
          alert("Please install MetaMask or a compatible wallet and then reload")
      }
      const [account] = await window.ethereum.request({method: 'eth_requestAccounts'})
      const walletClient = createWalletClient({
          account,
          transport: custom(window.ethereum)
      })
      
      window.goodSignature = () => {
        walletClient.signMessage({
            message: "${loginPrompt}${nonce}"
        }).then(signature => {
            const path= "/${config.idpDir}/signature/${nonce}/" + account + "/" + signature
            // window.location.href = path
            console.log(signature)
        })
      }

      window.badSignature = () => {
        const path= "/${config.idpDir}/signature/${nonce}/" + 
          getAddress("0x" + "BAD060A7".padEnd(40, "0")) + 
          "/0x" + "BAD0516".padStart(130, "0")
        window.location.href = path
      }
    </script>
  </head>
  <body>
    <h2>Please sign</h2>
    <button onClick="window.goodSignature()">
      Submit a good (valid) signature
    </button>
    <br/>
    <button onClick="window.badSignature()">
      Submit a bad (invalid) signature
    </button>
  </body>
</html>  
`
}


const idpRouter = express.Router()

idpRouter.get("/signature/:nonce/:account/:signature", async (req, res) => {

  const requestId = nonces[req.params.nonce]
  if (requestId === undefined) {
    res.send("Bad nonce")
    return ;
  }

  nonces[req.params.nonce] = undefined

  try {
    const validSignature = await verifyMessage({
      address: req.params.account,
      message: `${loginPrompt}${req.params.nonce}`,
      signature: req.params.signature
    })
    if (!validSignature)
      throw("Bad signature")
  } catch (err) {
    res.send("Error:" + err)
    return ;
  }
  const loginResponse = await idp.createLoginResponse(
    sp, 
    {
      authnContextClassRef: 'urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport',
      audience: sp.entityID,
      extract: {
        request: {
          id: requestId
        }
      },
      signingKey: { privateKey: idpPrivateKey, publicKey: config.idpCert }  // Ensure signing
    },
    "post",
    {
      email: req.params.account + "@bad.email.address"
    }
  );

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
      res.send(getSignaturePage(samlRequest["samlp:AuthnRequest"]["@_ID"]))
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