import { QueryEngine } from "@comunica/query-sparql";
//import { QueryEngine as QueryEngine2 } from "@comunica/query-sparql-link-traversal-solid";
import { QueryEngine as QueryEngine2 } from "@mvbtst/comunica-lt-test-conf";

const engineDefault = new QueryEngine;
const engineDatasources = new QueryEngine2;

import {
  getDefaultSession,
  fetch as authFetch,
} from "@inrupt/solid-client-authn-browser";

/**
 * A class wrapping the Comunica engines we need, used for all but login actions.
 */
class ComunicaEngineWrapper {

  _fetchStatusNumber;
  _underlyingFetchFunction;

  constructor() {
    this._fetchSuccess = {};
    this._fetchStatusNumber = {};
    this._underlyingFetchFunction = undefined;
  }

  /**
   * Resets the engine and all we maintained here about executed queries
   */
  reset() {
    engineDefault.invalidateHttpCache();
    engineDatasources.invalidateHttpCache();
    this._fetchSuccess = {};
    this._fetchStatusNumber = {};
    this._underlyingFetchFunction = undefined;
  }

  getFetchSuccess(arg) {
    return this._fetchSuccess[arg];
  }

  getFetchStatusNumber(arg) {
    return this._fetchStatusNumber[arg];
  }

  getUnderlyingFetchFunction() {
    return this._underlyingFetchFunction;
  }

  /**
  * Executes one generic SPARQL query with the Comunica engine
  * 
  * Supports the following callback functions. Forward only the ones you need.
  * - "variables": will be called once with an array of variable names, in case of a SELECT query
  * - "bindings": will be called for every bindings combo, in case of a SELECT query
  * - "quads": will be called for every quad, in case of a CONSTRUCT query
  * - "boolean": will be called for the resulting boolean, in case of an ASK query
  * 
  * @param {string} queryText - the SPARQL query text
  * @param {object} context - the context to provide to the Comunica engine
  * @param {object} callbacks - an object contains the callback functions you specify
  * @returns {void} when the query has finished
  */
  async query(queryText, context, callbacks) {
    try {
      this._prepareQuery(context);
      let result = await engineDefault.query(queryText, context);
      switch (result.resultType) {
        case 'bindings':
          const metadata = await result.metadata();
          const variables = metadata.variables.map((val) => {
            return val.value;
          });
          if (callbacks["variables"]) {
            callbacks["variables"](variables);
          }
          const bindingsStream = await result.execute();
          await new Promise((resolve, reject) => {
            if (callbacks["bindings"]) {
              bindingsStream.on('data', (bindings) => {
                callbacks["bindings"](bindings);
              });
            }
            bindingsStream.on('end', resolve);
            bindingsStream.on('error', reject);
          });
          break;
        case 'quads':
          const quadStream = await result.execute();
          await new Promise((resolve, reject) => {
            if (callbacks["quads"]) {
              quadStream.on('data', (quad) => {
                callbacks["quads"](quad);
              });
            }
            quadStream.on('end', resolve);
            quadStream.on('error', reject);
          });
          break;
        case 'boolean':
          const answer = await result.execute();
          if (callbacks["boolean"]) {
            callbacks["boolean"](answer);
          }
          break;
        default:
          break;
      }
    } catch (error) {
      this.reset();
      throw error;
    }
  }

  /**
  * Executes one SPARQL SELECT query with the Comunica engine
  * 
  * Supports the following options.
  * - engine: 
  *   - "default": use the default Comunica query (this is the default anyway)
  *   - "datasources": use a Comunica query engine configured to discover datasources recursively
  * 
  * @param {string} queryText - the SPARQL SELECT query text
  * @param {object} context - the context to provide to the Comunica engine
  * @param {object} options - an object with options
  * @param {string} options.engine - selects which engine to use
  * @returns {Promise <BindingsStream>} Promise to the bindings stream
  */
  async queryBindings(queryText, context, options) {
    const opts = options || {};
    let engine;
    switch (opts.engine) {
      case "default":
      case undefined:
        engine = engineDefault;
        break
      case "datasources":
        engine = engineDatasources;
        break;
      default:
        throw new Error("Unsupported engine requested");
    }
    try {
      this._prepareQuery(context);
      return engine.queryBindings(queryText, context);
    } catch (error) {
      this.reset();
      throw error;
    }
  }

  /**
   * Prepares a call to any engine's query function
   *
   * @param {object} context - the context that will be used
   */
  _prepareQuery(context) {
    // avoid faulty fetch status for sources cached in Comunica
    for (const source of context.sources) {
      this._fetchSuccess[source] = true;
    }
    this._underlyingFetchFunction = fetch;
    if (getDefaultSession().info.isLoggedIn) {
      this._underlyingFetchFunction = authFetch;
    }
    context.fetch = ComunicaEngineWrapper._getWrappedFetchFunction(this._underlyingFetchFunction, this);
  }

  /**
   * Returns a function that wraps the underlying fetch function and sets the fetch success information in member variables of _this.
   * 
   * @param underlyingFetchFunction - the underlying fetch functin
   * @param {ComunicaEngineWrapper} _this - the calling ComunicaEngineWrapper object
   * @returns {Function} that function.
   */
  static _getWrappedFetchFunction(underlyingFetchFunction, _this) {
    const wrappedFetchFunction = async (arg) => {
      try {
        const response = await underlyingFetchFunction(arg, {
          headers: {
            Accept: "application/n-quads,application/trig;q=0.9,text/turtle;q=0.8,application/n-triples;q=0.7,*/*;q=0.1"
          }
        });
        _this._fetchSuccess[arg] = response.ok;
        _this._fetchStatusNumber[arg] = response.status;
        return response;
      }
      catch (error) {
        _this._fetchSuccess[arg] = false;
        throw error;
      }
    }

    return wrappedFetchFunction;
  }
}

const comunicaEngineWrapper = new ComunicaEngineWrapper();
export default comunicaEngineWrapper;
