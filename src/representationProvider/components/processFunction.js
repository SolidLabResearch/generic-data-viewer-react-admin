import { termToString } from "rdf-string";

/**
 *
 * @param {object} record an object of RDF/JS objects
 * @param {string} source the key of record which is to be processed
 * @returns {string} the id or value of the record at the given source key
 */
export function getRawData(record, source) {
  const value = record[source];
  const termString = termToString(value);
  if (termString) {
    return termString;
  }
  return value;
}