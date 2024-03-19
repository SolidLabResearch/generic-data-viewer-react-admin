import CheckIcon from "@mui/icons-material/Check";
import GppMaybeIcon from '@mui/icons-material/GppMaybe';
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

const VERIFICATION_STATES = {
  FAILED: 0,
  SUCCESS: 1,
  ERROR: 2
}
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
  const [isVerified, setIsVerified] = useState('NOT_VERIFIED');
  const [needsVerification, setNeedsVerification] = useState(false);

  function isValidVerifiableCredential(credential) {
    // Check for the '@context' property - it's necessary to understand the JSON keys and values
    const hasContext = credential['@context'] !== undefined;

    // Check for the 'type' property and that it includes 'VerifiableCredential'
    const hasType = Array.isArray(credential.type) && credential.type.includes('VerifiableCredential');

    // Check for the 'credentialSubject' property which represents who the credential is about
    const hasCredentialSubject = credential.credentialSubject !== undefined;

    // Check for the 'issuer' property which represents who issued the credential
    const hasIssuer = credential.issuer !== undefined;

    return hasContext && hasType && hasCredentialSubject && hasIssuer;
  }

  const getVCForSourceOption1 = async (source, fetchFunction) => {
    console.info('getVCForSourceOption1: VC is a separate resource located at `${source}-vc`')
    const vcResponse = await fetchFunction(`${source}-vc`)
    if(!vcResponse.ok)
      throw new Error(`Failed fetching VC for source ${source}. Details: ${vcResponse.statusText} (${vcResponse.status})`)
    const vc = await(vcResponse).json()
    return vc
  }

  const getVCForSourceOption2 = async (source, fetchFunction) => {
    console.info('getVCForSourceOption2: source is the actual VC')
    const response = await fetchFunction(source,{headers: {
        'accept': 'application/ld+json'
      }});
    const vc = await response.json()
    console.log({vc})
    return vc
  }

  // This function should be replaced by the actual verification function
  const verifyFunction = async (source, fetchFunction) => {
    try {

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
      const controllerDoc =
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

      jdl.addStatic(keyExport.controller, controllerDoc)
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


      // const vc  = await getVCForSourceOption1(source, fetchFunction)
      const vc  = await getVCForSourceOption2(source, fetchFunction)
      if(!isValidVerifiableCredential(vc))
        throw new Error('Not verifiable!')


      // Verify
      const verificationResult = await jsigs.verify(
          vc,
          {
            suite,
            purpose: new purposes.AssertionProofPurpose(),
            documentLoader
          }
      )
      
      return verificationResult.verified ? VERIFICATION_STATES.SUCCESS : VERIFICATION_STATES.FAILED

    } catch (error) {
      console.error(error)
      return VERIFICATION_STATES.ERROR
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
      switch (isVerified) {
        case VERIFICATION_STATES.SUCCESS:
          return (
            <Tooltip title="Verification succeeded">
              <CheckIcon size="small"/>
            </Tooltip>
        );
          break;
        case VERIFICATION_STATES.FAILED:
          return (
              <Tooltip title="Verification failed">
                <CancelIcon size="small"/>
              </Tooltip>
          );
          break;
        case VERIFICATION_STATES.ERROR:
          return (
              <Tooltip title="Verification error">
                <GppMaybeIcon size="small"/>
              </Tooltip>
          );
          break;
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
