import { ProxyHandlerStatic } from "@comunica/actor-http-proxy";
import config from "../config.json";
import { QueryEngine } from "@comunica/query-sparql";
import {
  getDefaultSession,
  fetch as authFetch,
} from "@inrupt/solid-client-authn-browser";
import { HttpError } from "react-admin";
import { Generator, Parser } from "sparqljs";
import NotImplementedError from "../NotImplementedError";
import { Term } from "sparqljs";

const myEngine = new QueryEngine();

let proxyHandler = undefined;
if (config.httpProxy) {
  proxyHandler = new ProxyHandlerStatic(config.httpProxy);
}

if (!config.queryFolder) {
  config.queryFolder = "./";
}

if (config.queryFolder.substring(config.queryFolder.length - 1) !== "/") {
  config.queryFolder = `${config.queryFolder}/`;
}

export default {
  getList: async function getList(queryName, { pagination, sort, filter, meta }) {
    // TODO delete
    console.log("DEBUGGING - entering getList()");
    const query = findQueryWithId(queryName);
    query.limit = pagination.perPage;
    query.offset = (pagination.page - 1) * pagination.perPage;
    query.sort = sort;

    handleComunicaContextCreation(query);

    if (query.sourcesIndex) {
      const additionalSources = await addComunicaContextSourcesFromSourcesIndex(query.sourcesIndex);
      query.comunicaContext.sources = [...new Set([...query.comunicaContext.sources, ...additionalSources])];
    }

    if (meta && meta.variables) {
      query.variableValues = meta.variables;
    }

    try {
      let results = await executeQuery(query);
      if (Object.keys(filter).length > 0) {
        results = results.filter((result) => {
          return Object.keys(filter).every((key) => {
            return result[key] === filter[key];
          });
        });
      }
      // TODO delete
      console.log(`DEBUGGING - leaving getList(), total = ${query.totalItems}`);
      return {
        data: results,
        total: query.totalItems
      };
    } catch (error) {
      // TODO delete
      console.log("DEBUGGING - leaving getList() with an error: ", error);
      throw (error);
    }
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
 *
 * @param {number} id - identifier of a query
 * @returns {object} the query with the given id from the config file and additional information about it, if it exists.
 */
function findQueryWithId(id) {
  return config.queries.find((query) => query.id === id);
}

/**
 * Fetches the the query file from the given query and returns its text.
 * @param {object} query - the query which is to be executed and additional information about the query.
 * @returns {string} the text from the file location provided by the query relative to query location defined in the config file.
 */
async function fetchQuery(query) {
  try {
    const result = await fetch(`${config.queryFolder}${query.queryLocation}`);
    const parser = new Parser();
    let rawText = await result.text();

    if (query.variableValues) {
      rawText = replaceVariables(rawText, query.variableValues);
    }

    query.rawText = rawText;
    const parsedQuery = parser.parse(rawText);
    if (!query.variableOntology) {
      query.variableOntology = findPredicates(parsedQuery);
    }
    if (parsedQuery.limit !== undefined && query.offset + query.limit > parsedQuery.limit) {
      parsedQuery.limit = parsedQuery.limit - query.offset;
    } else {
      parsedQuery.limit = query.limit;
    }
    if (parsedQuery.offset) {
      parsedQuery.offset += query.offset;
    } else {
      parsedQuery.offset = query.offset;
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

  return rawText
}

/**
 * Given a query and an object, this function returns the predicate of the object in the query.
 * @param {object} query - the paresed query in which the predicate is to be looked for.
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
 * A function that executes a given query and processes every result.
 * @param {object} query - the query which is to be executed and additional information about the query.
 * @returns {Array<Term>} the results of the query
 */
async function executeQuery(query) {
  try {
    query.queryText = await fetchQuery(query);
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
          Accept: "application/n-quads,application/trig;q=0.95,application/ld+json;q=0.9,application/n-triples;q=0.8,*/*;q=0.1"
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
 * @param {object} query - the query which is to be executed and additional information about the query.
 * @returns {Array<Term>} the results of the query
 */
async function handleQueryExecution(execution, query) {
  try {
    let variables;
    const resultType = execution.resultType;
    if (execution.resultType !== "boolean") {
      const metadata = await execution.metadata();
      query.totalItems = await countQueryResults(query);
      variables = metadata.variables.map((val) => {
        return val.value;
      });
    }
    return queryTypeHandlers[resultType](await execution.execute(), variables);
  } catch (error) {
    throw new HttpError(error.message, 500);
  }
}

/**
 *
 * @param {object} query - the query which is to be executed and additional information about the query.
 * @returns {number} the actual number of results in the query, if it were executed
 */
async function countQueryResults(query) {
  const parser = new Parser();
  const parsedQuery = parser.parse(query.rawText);
  const distinctInitial = parsedQuery.distinct;
  const offsetInitial = parsedQuery.offset;
  const limitInitial = parsedQuery.limit;
  parsedQuery.queryType = "SELECT";
  parsedQuery.distinct = false;
  parsedQuery.offset = 0;
  if (parsedQuery.limit) {
    delete parsedQuery.limit;
  }
  parsedQuery.variables = [
    {
      expression: {
        type: "aggregate",
        aggregation: "count",
        expression: { termType: "Wildcard", value: "*" },
        distinct: distinctInitial
      },
      variable: { termType: "Variable", value: "totalItems" },
    },
  ];
  const generator = new Generator();
  const countQuery = generator.stringify(parsedQuery);
  const bindings = await myEngine.queryBindings(countQuery, {
    sources: query.comunicaContext.sources,
    fetch: fetch,
    httpProxyHandler: proxyHandler,
  });
  let totalItems = parseInt((await bindings.toArray())[0].get("totalItems").value);
  if (offsetInitial) {
    totalItems -= offsetInitial;
  }
  if (limitInitial && totalItems > limitInitial) {
    totalItems = limitInitial;
  }
  return totalItems;
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

const addComunicaContextSourcesFromSourcesIndex = async (sourcesIndex) => {
  const sourcesList = [];
  try {
    const result = await fetch(`${config.queryFolder}${sourcesIndex.queryLocation}`);
    const queryStringIndexSource = await result.text();

    const bindingsStream = await myEngine.queryBindings(queryStringIndexSource, {
      sources: [sourcesIndex.url],
    });

    await new Promise((resolve, reject) => {
      bindingsStream.on('data', (binding) => {
        const source = binding.get('object').value;
        if (!sourcesList.includes(source)) {
          sourcesList.push(source);
        }
      });
      bindingsStream.on('end', resolve);
      bindingsStream.on('error', reject);
    });
  }
  catch (error) {
    throw new Error(`Error adding sources from index: ${error.message}`);
  }

  return sourcesList;
};

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