import { ProxyHandlerStatic } from "@comunica/actor-http-proxy";
import config from "../config.json" assert { type: "json" };
import { QueryEngine } from "@comunica/query-sparql";
import { getDefaultSession, fetch as authFetch } from "@inrupt/solid-client-authn-browser";
import { HttpError } from "react-admin";

const myEngine = new QueryEngine();

let proxyHandler = undefined;
if (config.httpProxy) {
  proxyHandler = new ProxyHandlerStatic(config.httpProxy);
}

export default {
  getList: async function getList(queryName, { pagination, sort, filter }) {
    let results = await executeQuery(findQueryWithId(queryName));
    if(Object.keys(filter).length > 0){
      results = results.filter((result) => {
        return Object.keys(filter).every((key) => {
          return result[key] === filter[key];
        });
      });
    }
    const { page, perPage } = pagination;
    const start = (page - 1) * perPage;
    if(start > results.length){
      results = []
    } 
    else if(start + perPage > results.length - 1){
      results = results.slice(start, results.length)
    }
    else{
      results = results.slice(start, start + perPage)
    }

    console.log({
      data: results,
      total: results.length,
    })
    return {
      data: results,
      total: results.length,
    };
  },
  getOne: async function getOne(_, { id }) {
    console.log("getOne");
    return executeQuery(findQueryWithId(id));
  },
  getMany: async function getMany(_, { ids }) {
    console.log("getMany");
    return {
      data: await Promise.all(
        executeQuery(ids.map((id) => findQueryWithId(id)))
      ),
    };
  },
  getManyReference: async function getManyReference(_, { target, id }, __, ___) {
    console.error("getManyReference not implemented");
  },
  create: async function create(_, { data }) {
    console.error("create not implemented");
  },
  update: async function update(_, { id, data }) {
    console.error("update not implemented");
  },
  updateMany: async function updateMany(_, { ids, data }) {
    console.error("updateMany not implemented");
  },
  delete: async function deleteOne(_, { id }) {
    console.error("deleteOne not implemented");
  },
  deleteMany: async function deleteMany(_, { ids }) {
    console.error("deleteMany not implemented");
  }
};


function findQueryWithId(id) {
  return config.queries.find((query) => query.id === id);
}

function findQueryByName(name) {
  return config.queries.find((query) => query.name === name);
}

/**
 * Fetches the the query file from the given query and returns its text.
 * @param {query} query the query which is to be executed
 * @returns the text from the file location provided by the query relative to query location defined in the config file.
 */
async function fetchQuery(query) {
  try {
    // const result = await fetch(`${config.queryFolder}${query.queryLocation}`);
    return `SELECT ?name ?deathDate_int WHERE {
      ?person a dbpedia-owl:Artist;
              rdfs:label ?name;
              dbpedia-owl:birthPlace [ rdfs:label "York"@en ].
      FILTER LANGMATCHES(LANG(?name),  "EN")
      OPTIONAL { ?person dbpprop:dateOfDeath ?deathDate_int. }
    }`;
  } catch (error) {
    throw new HttpError(error.message, 500);
  }
}

/**
 * A function that executes a given query and processes every result.
 * @param {query} query the query which is to be executed
 */
async function executeQuery(query) {
  try {
    query.queryText = await fetchQuery(query);
    console.log(query.queryText)
    const fetchFunction = getDefaultSession().info.isLoggedIn
      ? authFetch
      : fetch;
    return handleQueryExecution(
      await myEngine.query(query.queryText, {
        sources: query.sources,
        fetch: fetchFunction,
        httpProxyHandler: proxyHandler,
      }),
      query
    );
  } catch (error) {
    throw new HttpError(error.message, 500);
  }
}

/**
 * A function that given a QueryType processes every result.
 *
 * @param {QueryType} execution a query execution
 * @param {query} query the query which is being executed
 */
async function handleQueryExecution(execution, query) {
  try {
    let variables;
    const resultType = execution.resultType;

    if (execution.resultType === "bindings") {
      const metadata = await execution.metadata();
      variables = metadata.variables.map((val) => {
        return val.value;
      });
    }

    return queryTypeHandlers[execution.resultType](
      await execution.execute(),
      variables
    );
  } catch (error) {
    throw new HttpError(error.message, 500);
  }
}

const queryTypeHandlers = {
  bindings: configureBindingStream,
  quads: configureQuadStream,
  boolean: configureBool,
};

/**
 * Configures how a boolean query gets processed.
 * @param {Boolean} result the result of a boolean query
 */
function configureBool(result) {
  adder(result);
}

/**
 *
 * @param {List<String>} variables all the variables of the query behind the binding stream.
 */
async function configureIterator(iterator, variables) {
  try {
    const results = await iterator.toArray();
    return results.map((result, index) => {
      let newResults = {};
      for (let variable of variables) {
        newResults[variable.split('_')[0]] = result.get(variable);
      }
      newResults.id = index;
      return newResults;
    });
  } catch (error) {
    console.error(error);
  }
}

/**
 * Configures how a query resulting in a stream of quads should be processed.
 * @param {AsyncIterator<Quad> & ResultStream<Quad>>} quadStream a stream of Quads
 * @param {List<String>} variables all the variables of the query behind the binding stream.
 */
function configureQuadStream(quadStream) {
  return configureIterator(quadStream, [
    "subject",
    "predicate",
    "object",
    "graph",
  ]);
}

/**
 * Configures how a query resulting in a stream of bindings should be processed.
 * @param {BindingStream} bindingStream a stream of Bindings
 * @param {List<String>} variables all the variables of the query behind the binding stream.
 */
function configureBindingStream(bindingStream, variables) {
  return configureIterator(bindingStream, variables);
}
