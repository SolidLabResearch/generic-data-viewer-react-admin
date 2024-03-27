import {CircularProgress, Tooltip} from "@mui/material";
import {Component, useState} from "react";
import QuestionMarkIcon from "@mui/icons-material/QuestionMark";
import {Button} from "react-admin";
import PropTypes from "prop-types";
import GppBadIcon from '@mui/icons-material/GppBad'; // FAILED
import VerifiedUserIcon from '@mui/icons-material/VerifiedUser'; // NOT VERIFIABLE
import PrivacyTipIcon from '@mui/icons-material/PrivacyTip'; // SUCCESS
import WarningIcon from '@mui/icons-material/Warning'; // ERROR

class API { // TODO: refactor
  constructor(origin, port, routes) {
    this.baseUrl = `${origin}:${port}`
    for (const r of routes) {
      this[r] = new URL(r, this.baseUrl).toString()
    }
  }
}
const vcAPI = new API('http://localhost', 4444, ['verify']) // TODO: make configurable
const VERIFICATION_STATES = {
  NOT_VERIFIED: 'NOT_VERIFIED',
  VERIFIED: 'VERIFIED',
  INVALID_SOURCE: 'INVALID_SOURCE',
  ERROR: 'ERROR'
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
  const [isVerified, setIsVerified] = useState(VERIFICATION_STATES.NOT_CHECKED);
  const [needsVerification, setNeedsVerification] = useState(false);

  // This function should be replaced by the actual verification function
  const verifyFunction = async (source, fetchFunction) => {
    try {
      console.log(`@verifyFunction: ${source}`)
      const response = await fetchFunction(source,{headers:{'accept':'application/json'}});
      const data = await response.json()

      // Use vc-service to verify source
      const verifyResponse = await fetchFunction(
          vcAPI.verify,
          {
            method: 'POST',
            headers: {'content-type': 'application/json'},
            body: JSON.stringify({verifiableCredential: data})
          }
      )

      if(verifyResponse.ok){
        const {
          validationResult: {valid, validationError},
          verificationResult: {verified, results, error: verificationError}
        } = await verifyResponse.json()

        if(valid) {
          if(verified) {
            return VERIFICATION_STATES.VERIFIED
          } else {
            return VERIFICATION_STATES.NOT_VERIFIED
          }

        } else {
          return VERIFICATION_STATES.INVALID_SOURCE
        }

      }

    } catch (error) {
      return VERIFICATION_STATES.ERROR;
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
        case VERIFICATION_STATES.VERIFIED:
          return (
              <Tooltip title="Verification succeeded">
                <VerifiedUserIcon size="small"/>
              </Tooltip>
          );
          break;
        case VERIFICATION_STATES.INVALID_SOURCE:
          return (
              <Tooltip title="No credential found to verify">
                <PrivacyTipIcon size="small"/>
              </Tooltip>
          );
          break;
        case VERIFICATION_STATES.NOT_VERIFIED:
          return (
              <Tooltip title="Verification failed">
                <GppBadIcon size="small"/>
              </Tooltip>
          );
          break;
        case VERIFICATION_STATES.ERROR:
          return (
              <Tooltip title="Error">
                <WarningIcon size="small"/>
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
