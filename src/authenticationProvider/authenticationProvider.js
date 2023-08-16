import { QueryEngine } from "@comunica/query-sparql";
import {
  getLiteral,
  getProfileAll,
  getThing,
  getUrl,
} from "@inrupt/solid-client";
import { getDefaultSession, fetch } from "@inrupt/solid-client-authn-browser";
import { FOAF } from "@inrupt/vocab-common-rdf";

const queryEngine = new QueryEngine();

export default {
  login: async function login({ type, value }) {
    const session = getDefaultSession();
    let idp;
    if (type !== "idp") {
      try {
        idp = await queryIDPfromWebId(value);
      } catch (error) {
        // Nothing to do here, the input `idpOrWebId` might be an IDP already
        throw new Error("Couldn't query the Identity Provider from the WebID");
      }
    }
    else{
      idp = value; 
    }

    if (!idp) {
      throw new Error("No IDP found");
    }

    try {
      await session.login({
        oidcIssuer: idp,
        redirectUrl: new URL("/", window.location.href).toString(),
        clientName: "Generic Data Viewer",
      });
    } catch (error) {
      throw new Error("Login failed");
    }
  },
  logout: async function logout() {
    const session = getDefaultSession();
    await session.logout();
    return false;
  },
  checkAuth: async function checkAuth() {
    const session = getDefaultSession();
    return session.info;
  },
  getPermissions: async function getPermissions() {
    const session = getDefaultSession();
    return { loggedIn: session.info.isLoggedIn };
  },
  checkError: async function checkError(error) {
    const session = getDefaultSession();
    if ((error.status === 401 || error.status === 403)) {
      if(session.info.isLoggedIn){
        throw new Error("You don't have access to this resource.");
      }
      else{
        throw new Error("You don't have access to this resource. You might need to log in.");
      }
    }
    
  },
  getIdentity: async function getIdentity() {
    const session = getDefaultSession();
    const webId = session.info.webId;
    const identity = {};
    if (!session.info.isLoggedIn) {
      return identity;
    }
    try {
      const dataSet = await getProfileAll(webId, { fetch: fetch });
      const profile = dataSet.webIdProfile;
      const webIdThing = getThing(profile, webId);
      identity.fullName = getName(webIdThing);
      identity.avatar = getProfilePicture(webIdThing);
    } catch (error) {
      return identity;
    }
    return identity;
  },
};

/**
 * Looks up the IDP of a WebID by querying the WebID .
 * @param {URL} webId the WebID to query the IDP from
 * @returns {?Promise<URL>} the first IDP of the WebID or undefined if no IDP is found in the WebID document
 */
async function queryIDPfromWebId(webId) {
  let bindings;
  try {
    bindings = await queryEngine.queryBindings(
      `SELECT ?idp WHERE { <${webId}> <http://www.w3.org/ns/solid/terms#oidcIssuer> ?idp }`,
      { sources: [webId] }
    );
  } catch (error) {
    queryEngine.invalidateHttpCache(webId);
    throw new Error("Couldn't query the WebID");
  }

  const idps = await bindings.toArray();
  if (idps.length === 0) {
    return undefined;
  }
  return idps[0].get("idp").value;
}

/**
 *
 * @param {object} webIdThing the webId (actually of type ProfileAll, but importing this throws an error https://github.com/SolidLabResearch/generic-data-viewer-react-admin/issues/15) document to get the name from
 * @returns {?string} either the name or undefined if no foaf:name is found
 */
function getName(webIdThing) {
  const literalName = getLiteral(webIdThing, FOAF.name);
  if (literalName) {
    return literalName.value;
  } else {
    return undefined;
  }
}

/**
 *
 * @param {object} webIdThing the webId (actually of type ProfileAll, but importing this throws an error https://github.com/SolidLabResearch/generic-data-viewer-react-admin/issues/15) document to get the profile picture from
 * @returns {?string} either a url to the profile picture or undefined if no foaf:img is found
 */
function getProfilePicture(webIdThing) {
  return getUrl(webIdThing, FOAF.img);
}
