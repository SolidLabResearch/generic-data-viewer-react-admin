import React, { useState, useEffect } from 'react';
import { useResourceContext, Loading, useDataProvider } from "react-admin";
import { useLocation, useNavigate } from 'react-router-dom';
import { Component } from "react";
import TemplatedQueryForm from "./TemplatedQueryForm.jsx";
import ListResultTable from "./ListResultTable.jsx";

import configManager from '../../configManager/configManager.js';

/**
 * A wrapper component around ListResultTable, to support templated queries
 * @param {object} props - the props passed down to the component
 * @returns {Component} the wrapper component
 */
const TemplatedListResultTable = (props) => {

  const dataProvider = useDataProvider();
  const resource = useResourceContext();
  const query = configManager.getQueryWorkingCopyById(resource);

  const location = useLocation();
  const navigate = useNavigate();
  const [submittedVariables, setSubmittedVariables] = useState({});
  const [submitted, setSubmitted] = useState(false);
  const [searchPar, setSearchPar] = useState({});
  const [loading, setLoading] = useState(true);
  const [queryVariables, setQueryVariables] = useState(query.variables);


  useEffect(() => {

    const fetchQuery = async () => {

      if (query.variables || query.indirectVariables){
        // Handles the query variables (defined and indirect ones)
        const vars = await dataProvider.indirectVariables(query);
        setQueryVariables(vars);
      }
     
      setLoading(false);
    };

    fetchQuery();
  }, [resource]);

  const areQueryVariablesLoaded = queryVariables !== undefined;
  let tableEnabled = !areQueryVariablesLoaded;


  //HERE THE CODE MUST WAIT UNTIL THE  `query.variables` ARE LOADED CORRECTLY
  if (loading) {
    return <Loading loadingSecondary={"The page is loading. Just a moment please."} />;
  }

  if (areQueryVariablesLoaded) {
    // Update variables from query parameters
    const queryParams = new URLSearchParams(location.search);
    const urlVariables = {};
    for (const variableName of Object.keys(queryVariables)) {
      if (queryParams.has(variableName)) {
        urlVariables[variableName] = queryParams.get(variableName);
      }
    }
    if (!equalSimpleObjects(submittedVariables, urlVariables)) {
      setSubmittedVariables(urlVariables);
    } else {
      tableEnabled = (Object.keys(submittedVariables).length === Object.keys(queryVariables).length);
    }
  }

  const onSubmit = (formVariables) => {

    if (!submitted) {
      setSearchPar(formVariables);
    }
    // Update query parameters from the TemplatedQueryForm fields
    const queryParams = new URLSearchParams(location.search);
    for (const [variableName, variableValue] of Object.entries(formVariables)) {
      if (variableValue) {
        queryParams.set(variableName, variableValue);
      }
    }

    const queryString = queryParams.toString();
    if (queryString.length > 0) {
      if (!submitted) setSubmitted(true);

      navigate(`?${queryString}`);
    }
  }

  const changeVariables = () => {
    setSubmitted(false);
    navigate();
  }

  return (
    <>
      {areQueryVariablesLoaded && !tableEnabled &&
        <TemplatedQueryForm
          variableOptions={queryVariables}
          onSubmit={onSubmit}
          submitted={submitted}
          searchPar={searchPar}
          resource={resource}
        />
      }
      {tableEnabled && <ListResultTable {...props} resource={resource} variables={submittedVariables} changeVariables={changeVariables} submitted={submitted} />}
    </>
  )
}

/**
 * Check if two objects have the same property values (of type a primitive value or a string)
 * @param {object} obj1 - the first object
 * @param {object} obj2 - the second object
 * @returns {boolean} true means equal
 */
function equalSimpleObjects(obj1, obj2) {
  if (Object.keys(obj1).length !== Object.keys(obj2).length) {
    return false;
  }
  for (const key1 in obj1) {
    if (obj1[key1] !== obj2[key1]) {
      return false;
    }
  }
  return true;
}


export default TemplatedListResultTable;
