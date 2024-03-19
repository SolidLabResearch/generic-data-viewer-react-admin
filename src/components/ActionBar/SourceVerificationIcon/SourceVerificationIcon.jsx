import CheckIcon from "@mui/icons-material/Check";
import {CircularProgress, Tooltip} from "@mui/material";
import {Component, useState} from "react";
import QuestionMarkIcon from "@mui/icons-material/QuestionMark";
import {Button} from "react-admin";
import CancelIcon from "@mui/icons-material/Cancel";
import PropTypes from "prop-types";
import jsigs, {purposes} from 'jsonld-signatures'
import * as Ed25519Multikey from '@digitalbazaar/ed25519-multikey';
import {Ed25519VerificationKey2020} from
      '@digitalbazaar/ed25519-verification-key-2020';
import {Ed25519Signature2020, suiteContext} from
      '@digitalbazaar/ed25519-signature-2020';
import ed25519Ctx from 'ed25519-signature-2020-context';

import {JsonLdDocumentLoader} from 'jsonld-document-loader';
import cred from 'credentials-context';
const {contexts: credentialsContexts, constants: {CREDENTIALS_CONTEXT_V1_URL}} =
    cred;
const jdl = new JsonLdDocumentLoader();


async function getKeypair() {
  const webId = 'http://localhost:8080/example/profile/card#me';
  const seed = new Uint8Array(32)
  seed.fill(0x01)
  const key = await Ed25519Multikey.generate({
    id: webId.replace('#me','#key'),
    controller: webId,
    seed
  })




  return key
}
async function main() {
  console.log('main()')

  const key = await getKeypair()
  const keyExport = await key.export({publicKey: true, secretKey:true})
  console.log(keyExport)
}
main().then().catch(console.error)
/**
 * @param {object} props - the props passed to the component
 * @param {object} props.context - the query context
 * @param {string} props.source - the source to check
 * @param {string} props.proxyUrl - the proxy url to use if the resource is accessed through a proxy
 * @returns {Component} an icon indicating whether the source was verified or not
 */
function SourceVerificationIcon({context, source, proxyUrl}) {
  let sourceUrl = source;
  if (context.useProxy) {
    sourceUrl = `${proxyUrl}${source}`;
  }

  const [isLoading, setIsLoading] = useState(true);
  const [isVerified, setIsVerified] = useState(false);
  const [needsVerification, setNeedsVerification] = useState(false);

  // This function should be replaced by the actual verification function
  const verifyFunction = async (source, fetchFunction) => {
    try {
      const response = await fetchFunction(source,{headers: {
        'accept': 'application/ld+json'
        }});

      const payload = await response.json()

      const key = await getKeypair()
      const keyExport = await key.export({publicKey: true, secretKey:true})

      // const unsignedCredential = {
      //   '@context': [
      //     'https://www.w3.org/2018/credentials/v1',
      //
      //   ],
      //   // id: 'http://example.edu/credentials/1872',
      //   type: [ 'VerifiableCredential'],
      //   issuer: keyExport.controller,
      //   issuanceDate: '2010-01-01T19:23:24Z',
      //   credentialSubject: payload
      // };
      //
      /**
       * Document loader creation
       */
      const controlledDoc =
          {
            "@context": [
              "https://www.w3.org/ns/did/v1"
            ],
            "id": keyExport.controller,
            "verificationMethod": [
              keyExport
            ],
            "assertionMethod": [
              keyExport.id
            ]
          }

      jdl.addStatic(keyExport.controller, controlledDoc)
      jdl.addStatic(keyExport.id, keyExport)
      jdl.addStatic(
          CREDENTIALS_CONTEXT_V1_URL,
          credentialsContexts.get(CREDENTIALS_CONTEXT_V1_URL)
      );
      jdl.addStatic(ed25519Ctx.CONTEXT_URL, ed25519Ctx.CONTEXT);

      // suite
      const suite = new Ed25519Signature2020({key})
      const dl = jdl.build()
      const documentLoader = async (url) => {
        console.log({url})
        return await dl(url)
      }



      // const vc = await jsigs.sign(
      //     unsignedCredential,
      //     {
      //       suite,
      //       purpose: new purposes.AssertionProofPurpose(),
      //       documentLoader
      //     }
      // )
      //
      // console.log(vc)

      const vcResponse = await fetchFunction(`${source}-vc`)
      if(!vcResponse.ok)
        throw new Error(`Failed fetching VC for source ${source}. Details: ${vcResponse.statusText} (${vcResponse.status})`)
      const vc = await(vcResponse).json()


      // Verify
      const verificationResult = await jsigs.verify(
          vc,
          {
            suite,
            purpose: new purposes.AssertionProofPurpose(),
            documentLoader
          }
      )
      console.log(verificationResult)
      // TODO: throw error when verified == false?
      return verificationResult.verified

    } catch (error) {
      console.error(error)
      return false;
    }
  };

  /**
   * Handle the request for source verification
   */
  function verify() {
    setNeedsVerification(true);
    verifyFunction(sourceUrl, context.underlyingFetchFunction).then((result) => {
      setIsVerified(result);
      setIsLoading(false);
    })
  }

  if (needsVerification) {
    if (isLoading) {
      return <CircularProgress size={20}/>;
    } else {
      if (isVerified) {
        return (
          <Tooltip title="Verification succeeded">
            <CheckIcon size="small"/>
          </Tooltip>
        );
      } else {
        return (
          <Tooltip title="Verification failed">
            <CancelIcon size="small"/>
          </Tooltip>
        );
      }
    }
  } else {
    return (
      <Tooltip title="Verify source">
        <Button onClick={verify}>
          <QuestionMarkIcon size="small"/>
        </Button>
      </Tooltip>
    );
  }
}

SourceVerificationIcon.propTypes = {
  context: PropTypes.object.isRequired,
  source: PropTypes.string.isRequired,
  proxyUrl: PropTypes.string.isRequired,
}

export default SourceVerificationIcon;
