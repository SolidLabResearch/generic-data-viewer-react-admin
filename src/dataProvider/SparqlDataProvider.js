import { ProxyHandlerStatic } from "@comunica/actor-http-proxy";
import { QueryEngine } from "@comunica/query-sparql";
import {
  getDefaultSession,
  fetch as authFetch,
} from "@inrupt/solid-client-authn-browser";
import { HttpError } from "react-admin";
import { Generator, Parser } from "sparqljs";
import NotImplementedError from "../NotImplementedError";
import { Term } from "sparqljs";

import configManager from "../configManager/configManager";

const myEngine = new QueryEngine();

let config = configManager.getConfig();

let proxyHandler;

const setProxyHandler = () => {
  if (config.httpProxy) {
    proxyHandler = new ProxyHandlerStatic(config.httpProxy);
  } else {
    proxyHandler = undefined;
  }
};
setProxyHandler();

const onConfigChanged = (newConfig) => {
  config = newConfig;
  setProxyHandler();
};

configManager.on('configChanged', onConfigChanged);

export default {
  getList: async function getList(resource, { pagination, sort, filter, meta }) {
    // make a working copy of the query object found in the configuration, to prevent changing the configuration
    // this copy is extended here
    // rendering should occur based on this working copy
    const query = configManager.getQueryWorkingCopyById(resource);
    const limit = pagination.perPage;
    const offset = (pagination.page - 1) * pagination.perPage;
    query.sort = sort;

    handleComunicaContextCreation(query);

    if (query.sourcesIndex) {
      const additionalSources = await addComunicaContextSourcesFromSourcesIndex(query.sourcesIndex);
      query.comunicaContext.sources = [...new Set([...query.comunicaContext.sources, ...additionalSources])];
      console.log(query.comunicaContext.sources)
    }

    if (meta && meta.variables) {
      query.variableValues = meta.variables;
    }

    let results = await executeQuery(query);
    let totalItems = results.length;
    results = results.slice(offset, offset + limit);

    if (Object.keys(filter).length > 0) {
      results = results.filter((result) => {
        return Object.keys(filter).every((key) => {
          return result[key] === filter[key];
        });
      });
    }

    return {
      data: results,
      total: totalItems
    };
  },
  getOne: async function getOne() {
    // Our implementation doesn't use this function
    throw new NotImplementedError();
  },
  getMany: async function getMany() {
    // Our implementation doesn't use this function
    throw new NotImplementedError();
  },
  getManyReference: async function getManyReference() {
    throw new NotImplementedError();
  },
  create: async function create() {
    throw new NotImplementedError();
  },
  update: async function update() {
    throw new NotImplementedError();
  },
  updateMany: async function updateMany() {
    throw new NotImplementedError();
  },
  delete: async function deleteOne() {
    throw new NotImplementedError();
  },
  deleteMany: async function deleteMany() {
    throw new NotImplementedError();
  },
  queryEngine: myEngine
};

/**
 * Fetches the query file and builds the final query text.
 * @param {object} query - the query object working copy
 * @returns {string} the built query text
 */
async function buildQueryText(query) {
  try {
    let rawText = await configManager.getQueryText(query);

    if (query.variableValues) {
      rawText = replaceVariables(rawText, query.variableValues);
    }

    query.rawText = rawText;
    const parser = new Parser();
    const parsedQuery = parser.parse(rawText);
    if (!query.variableOntology) {
      query.variableOntology = findPredicates(parsedQuery);
    }
    if (!parsedQuery.order && query.sort && query.sort.field !== "id") {
      const { field, order } = query.sort;
      parsedQuery.order = [
        {
          expression: { termType: "Variable", value: field },
          descending: order === "DESC",
        },
      ];
    }
    const generator = new Generator();
    return generator.stringify(parsedQuery);
  } catch (error) {
    throw new HttpError(error.message, 500);
  }
}

/**
 * Replace the variable placeholders in a query's raw text by the specified value.
 * @param {string} rawText - the raw text of a query.
 * @param {object} variables - an object containing the variable names and specified values (as strings).
 * @returns {string} the resulting raw text of the query after replacing the variables.
 */
function replaceVariables(rawText, variables) {
  for (const [variableName, variableValue] of Object.entries(variables)) {
    // do not surround with double quotes here; add double quotes in the input if needed!
    rawText = rawText.replace("$" + variableName, variableValue);
  }

  return rawText;
}

/**
 * Given a query and an object, this function returns the predicate of the object in the query.
 * @param {object} query - the parsed query in which the predicate is to be looked for.
 * @returns {object} an object with the variable as key and the predicate as value.
 */
function findPredicates(query) {
  const ontologyMapper = {};
  if (!query.variables) {
    return query;
  }
  if (query.where) {
    for (const part of query.where) {
      if (part.triples) {
        for (const triple of part.triples) {
          if (triple.predicate.termType !== "Variable") {
            ontologyMapper[triple.object.value] = triple.predicate.value;
          }
        }
      }
    }
  }
  return ontologyMapper;
}

/**
 * Executes the query in scope and processes every result.
 * @param {object} query - the query object working copy
 * @returns {Array<Term>} the results of the query
 */
async function executeQuery(query) {
  try {
    query.queryText = await buildQueryText(query);
    return handleQueryExecution(
      await myEngine.query(query.queryText, {
        ...generateContext(query.comunicaContext),
      }),
      query
    );
  } catch (error) {
    if (query.comunicaContext && query.comunicaContext.sources) {
      for (const source of query.comunicaContext.sources) {
        myEngine.invalidateHttpCache(source);
      }
    }
    throw new HttpError(error.message, 500);
  }
}

/**
 * Generates the context for a query execution to be passed to Comunica engine when querying.
 * @param {object} context - the context for the query given in the config file.
 * @returns {object} the context for a query execution to be passed to Comunica engine when querying.
 */
function generateContext(context) {
  if (!context) {
    throw new HttpError("No context provided", 500);
  }
  if (!context.sources) {
    throw new HttpError("No sources provided", 500);
  }

  if (!context.fetchSuccess) {
    context.fetchSuccess = {};
    context.fetchStatusNumber = {};
    // avoid faulty fetch status for sources cached in Comunica
    for (const source of context.sources) {
      context.fetchSuccess[source] = true;
    }
  }

  let underlyingFetchFunction = fetch;
  if (getDefaultSession().info.isLoggedIn) {
    underlyingFetchFunction = authFetch;
  }

  context.underlyingFetchFunction = underlyingFetchFunction;
  context.fetch = statusFetch(underlyingFetchFunction, context);

  if (context.useProxy) {
    context.httpProxyHandler = proxyHandler;
  }

  return context;
}

/**
 * Given a fetch function, returns a function that wraps the fetch function and sets the fetchSuccess flag in the context.
 * @param {Function} customFetch - a fetch function to be wrapped
 * @param {*} context - the context for the query given in the config file.
 * @returns {Function} a function that wraps the fetch function and sets the fetchSuccess flag in the context.
 */
function statusFetch(customFetch, context) {
  const wrappedFetchFunction = async (arg) => {
    try {
      const response = await customFetch(arg, {
        headers: {
          Accept: "application/n-quads,application/trig;q=0.9,text/turtle;q=0.8,application/n-triples;q=0.7,*/*;q=0.1"
        }
      });
      context.fetchSuccess[arg] = response.ok;
      context.fetchStatusNumber[arg] = response.status;
      return response;
    }
    catch (error) {
      context.fetchSuccess[arg] = false;
      throw error;
    }
  }

  return wrappedFetchFunction;
}

/**
 * A function that given a QueryType processes every result.
 * @param {object} execution - a query execution
 * @param {object} query - the query element from the configuration
 * @returns {Array<Term>} the results of the query
 */
async function handleQueryExecution(execution, query) {
  try {
    let variables;
    const resultType = execution.resultType;
    if (execution.resultType !== "boolean") {
      const metadata = await execution.metadata();
      variables = metadata.variables.map((val) => {
        return val.value;
      });
    }
    return queryTypeHandlers[resultType](await execution.execute(), variables);
  } catch (error) {
    throw new HttpError(error.message, 500);
  }
}

const queryTypeHandlers = {
  bindings: configureBindingStream,
  quads: configureQuadStream,
};

/**
 * Configures how a query resulting in a stream of quads should be processed.
 * @param {object} quadStream - a stream of Quads
 * @returns {Array<Term>} the results of the query
 */
async function configureQuadStream(quadStream) {
  try {
    const results = (await quadStream.toArray()).flat();
    return results.map((result, index) => {
      const newResults = {
        subject: result.subject,
        predicate: result.predicate,
        object: result.object,
        graph: result.graph,
        id: index,
      };
      return newResults;
    });
  } catch (error) {
    throw new HttpError(error.message, 500);
  }
}

/**
 * Configures how a query resulting in a stream of bindings should be processed.
 * @param {object} bindingStream - a stream of Bindings
 * @param {Array<string>} variables - all the variables of the query behind the binding stream.
 * @returns {Array<Term>} the results of the query
 */
async function configureBindingStream(bindingStream, variables) {
  try {
    const results = await bindingStream.toArray();
    return results.map((result, index) => {
      const newResults = {};
      for (const variable of variables) {
        const value = result.get(variable);
        newResults[variable] = value;
      }
      newResults.id = index;
      return newResults;
    });
  } catch (error) {
    throw new HttpError(error.message, 500);
  }
}

/**
 * Add sources to the Comunica context from a sources index
 * @param {object} sourcesIndex - the sourcesIndex object as found in the configuration
 * @returns {array} array of sources found
 */
const addComunicaContextSourcesFromSourcesIndex = async (sourcesIndex) => {
  const sourcesList = [];
  try {
    let queryStringIndexSource;
    if (sourcesIndex.queryLocation){
      const result = await fetch(`${config.queryFolder}${sourcesIndex.queryLocation}`);
      queryStringIndexSource = await result.text();
    }else{
       queryStringIndexSource = sourcesIndex.queryString;
    }

    // const queryForSourceRetrieval = query
    // console.log(queryForSourceRetrieval)
    // queryForSourceRetrieval.comunicaContext.sources =  [query.sourcesIndex.url]

    const bindingsStream = await myEngine.queryBindings(queryStringIndexSource, {
      ...generateContext({sources: [sourcesIndex.url]}),
    });

    await new Promise((resolve, reject) => {
      bindingsStream.on('data', (bindings) => {
        // the bindings should have exactly one key (any name is allowed) and we accept the value as a source
        if (bindings.size == 1) {
          for (const term of bindings.values()) {
            const source = term.value;
            if (!sourcesList.includes(source)) {
              sourcesList.push(source);
            }
          }
        }
      });
      bindingsStream.on('end', resolve);
      bindingsStream.on('error', reject);
    });
  }
  catch (error) {
    throw new Error(`Error adding sources from index: ${error.message}`);
  }

  if (sourcesList.length == 0) {
    throw new Error(`The resulting list of sources is empty`);
  }

  return sourcesList;
};

/**
 * Creates/extends a comunicaContext property in a query
 * @param {object} query - the query element from the configuration
 */
const handleComunicaContextCreation = (query) => {

  if (!query.comunicaContext) {
    query.comunicaContext = {
      sources: [],
      lenient: true
    };
  }
  else {
    if (query.comunicaContext.lenient === undefined) {
      query.comunicaContext.lenient = true;
    }
    if (!query.comunicaContext.sources) {
      query.comunicaContext.sources = [];
    }
  }
};