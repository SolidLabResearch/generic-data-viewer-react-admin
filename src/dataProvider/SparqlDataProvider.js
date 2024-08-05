import { ProxyHandlerStatic } from "@comunica/actor-http-proxy";
import { HttpError } from "react-admin";
import { Generator, Parser } from "sparqljs";
import NotImplementedError from "../NotImplementedError";
import { Term } from "sparqljs";

import configManager from "../configManager/configManager";
import comunicaEngineWrapper from "../comunicaEngineWrapper/comunicaEngineWrapper";

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
      const additionalSources = await getSourcesFromSourcesIndex(query.sourcesIndex, query.comunicaContext.useProxy);
      query.comunicaContext.sources = [...new Set([...query.comunicaContext.sources, ...additionalSources])];
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
  indirectVariables: async function indirectVariables(query) {
    return await getIndirectVariables(query);
  },
};

/**
 * Fetches the query file and builds the final query text.
 * 
 * @param {object} query - the query object working copy
 * @returns {string} the built query text
 */
async function buildQueryText(query) {
  try {
    let rawText = await configManager.getQueryText(query);

    if (rawText === undefined) {
      throw new Error("Invalid query location.")
    }
    if (rawText === null || rawText === '') {
      throw new Error("Empty query text. Check your query and location.")
    }

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
 * 
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
 * 
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
 * 
 * @param {object} query - the query object working copy
 * @returns {Array<Term>} the results of the query
 */
async function executeQuery(query) {
  try {
    query.queryText = await buildQueryText(query);
    let variables;
    let results = [];
    let index = 0;
    const callbackVariables = (vars) => {
      variables = vars;
    };
    const callbackBindings = (bindings) => {
      const newResult = {};
      for (const variable of variables) {
        const term = bindings.get(variable);
        newResult[variable] = term;
      }
      newResult.id = index++;
      results.push(newResult);
    };
    const callbackQuads = (quad) => {
      const newResult = {
        subject: quad.subject,
        predicate: quad.predicate,
        object: quad.object,
        graph: quad.graph,
        id: index++
      }
      results.push(newResult);
    };
    await comunicaEngineWrapper.query(query.queryText,
      // !!! we need to make a copy of the context here (a shallow copy is fine); reason: concurrent calls
      { ...query.comunicaContext },
      { "variables": callbackVariables, "bindings": callbackBindings, "quads": callbackQuads });
    return results;
  } catch (error) {
    throw new HttpError(error.message, 500);
  }
}

/**
 * Gets sources from a sources index
 * 
 * @param {object} sourcesIndex - the sourcesIndex object as found in the configuration
 * @param {boolean} useProxy - true if the main query needs a proxy (in which case we implicitly use it to access the sources index too)
 * @returns {array} array of sources found
 */
async function getSourcesFromSourcesIndex(sourcesIndex, useProxy) {
  const sourcesList = [];
  try {
    let queryStringIndexSource;
    if (sourcesIndex.queryLocation) {
      const result = await fetch(`${config.queryFolder}${sourcesIndex.queryLocation}`);
      queryStringIndexSource = await result.text();
    } else {
      queryStringIndexSource = sourcesIndex.queryString;
    }

    const bindingsStream = await comunicaEngineWrapper.queryBindings(queryStringIndexSource,
      { sources: [sourcesIndex.url], httpProxyHandler: (useProxy ? proxyHandler : undefined) }, { engine: "datasources" });
    await new Promise((resolve, reject) => {
      bindingsStream.on('data', (bindings) => {
        for (const term of bindings.values()) {  // check for 1st value
          const source = term.value;
          if (!sourcesList.includes(source)) {
            sourcesList.push(source);
          }
          // we only want the first term, whatever the variable's name is (note: a for ... of loop seems the only way to access it)
          break;
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
}


/**
 * Creates/extends a comunicaContext property in a query
 * 
 * @param {object} query - the query element from the configuration
 */
function handleComunicaContextCreation(query) {
  if (!query.comunicaContext) {
    query.comunicaContext = {
      sources: [],
      lenient: true
    };
  } else {
    if (query.comunicaContext.lenient === undefined) {
      query.comunicaContext.lenient = true;
    }
    if (!query.comunicaContext.sources) {
      query.comunicaContext.sources = [];
    }
    if (query.comunicaContext.useProxy) {
      query.comunicaContext.httpProxyHandler = proxyHandler;
    }
  }
}

async function getIndirectVariables(query) {


  // This chunk of code is duplicated in order for the indirect queries having sources from a source index to work correctly.
  handleComunicaContextCreation(query);

  if (query.sourcesIndex) {
    const additionalSources = await getSourcesFromSourcesIndex(query.sourcesIndex, query.comunicaContext.useProxy);
    query.comunicaContext.sources = [...new Set([...query.comunicaContext.sources, ...additionalSources])];
  }
  // 


  let variables;
  let queryStringList = [];

  if (query.variables) {
    variables = query.variables
  } else {
    variables = {}
  }

  if (query.indirectVariables) {
    if (query.indirectVariables.queryLocations) {

      for (const location of query.indirectVariables.queryLocations) {
        // Checks for a valid queryLocation
        if (!location.endsWith('.rq')) {
          throw new Error("Wrong filetype for the indirectVariables query.")
        }
        const result = await fetch(`${config.queryFolder}${location}`);
        const queryStr = await result.text();

        if (queryStr === null || queryStr === '') {
          throw new Error("Empty variable query text. Check the query and locations for indirectVariables.")
        }
        queryStringList.push(queryStr);
      }
    }
    if (query.indirectVariables.queryStrings) {
      queryStringList = [...queryStringList, ...query.indirectVariables.queryStrings];
    }
    if (queryStringList.length == 0) {
      throw new Error("No indirectVariable queries were given...")
    }
  }

  try {
    for (const queryString of queryStringList) {
      const bindingsStream = await comunicaEngineWrapper.queryBindings(queryString,
        { sources: query.comunicaContext.sources, httpProxyHandler: (query.comunicaContext.useProxy ? proxyHandler : undefined) });
      await new Promise((resolve, reject) => {
        bindingsStream.on('data', (bindings) => {
          // see https://comunica.dev/docs/query/advanced/bindings/
          for (const [variable, term] of bindings) {
            const name = variable.value;
            if (!variables[name]) {
              variables[name] = [];
            }
            let variableValue;
            switch (term.termType) {
              case "Literal":
                // escape double quotes
                // example: This is a string containing some \"double quotes\"
                variableValue = `${term.value.replace(/"/g, '\\"')}`;
                // test whether there is a type specifier ^^...
                // this code is hacky, because it depends on undocumented term.id - cover it with sufficient test cases!
                if (/\"\^\^/.test(term.id)) {
                  // do not surround with double quotes
                  // example: 1
                } else {
                  // surround with double quotes
                  // example: "This is a string containing some \"double quotes\""
                  variableValue = `"${variableValue}"`;
                }
                // test whether there is a language tag @...
                // this code is hacky, because it depends on undocumented term.id - cover it with sufficient test cases!
                const lt = /\@(.*)$/.exec(term.id);
                if (lt) {
                  // append language tag
                  // example: "This is a string in English"@en
                  variableValue = `${variableValue}@${lt[1]}`;
                }
                break;
              case "NamedNode":
                // surround with triangle brackets
                // example: <https://www.example.com/data/o1>
                variableValue = `<${term.value}>`;
                break;
              default:
                break;
            }
            if (variableValue && !variables[name].includes(variableValue)) {
              variables[name].push(variableValue);
            }
          }
        });
        bindingsStream.on('end', resolve);
        bindingsStream.on('error', reject);
      });
    }
  }
  catch (error) {
    throw new Error(`Error adding indirect variables: ${error.message}`);
  }

  if (variables == {}) {
    throw new Error(`The variables are empty`);
  }
  return variables;
}
