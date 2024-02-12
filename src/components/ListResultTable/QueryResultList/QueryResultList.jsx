import { Component, useEffect, useState } from "react";
import { Datagrid, ListView, Title, useListContext } from "react-admin";
import ActionBar from "../../ActionBar/ActionBar";
import GenericField from "../../../representationProvider/GenericField";
import { Term } from "sparqljs";
import config from "../../../config";
import TableHeader from "./TableHeader/TableHeader";

/**
 * @param {object} props - the props passed down to the component
 * @returns {Component} custom ListViewer as defined by react-admin containing the results of the query with each variable its generic field. 
 */
function QueryResultList(props) {
  const { data } = useListContext(props);
  const [values, setValues] = useState([]);
  useEffect(() => {
    if (data && data.length > 0) {
      const setData = reduceDataToObject(data);
      delete setData.id;
      setValues(setData);
    }
  }, [data]);

  return (
    <>
      <Title title={config.title} />
      <ListView title=" " actions={<ActionBar />} empty={<ActionBar />} {...props}>
        {values && (
          <Datagrid header={<TableHeader config={config}/>} bulkActionButtons={false}>
            {Object.keys(values).map((key) => {
              return (
                <GenericField
                  key={key}
                  source={key}
                  label={key.split("_")[0]}
                />
              );
            })}
          </Datagrid>
        )}
      </ListView>
    </>
  );
}

/**
 *
 * @param {Array<Term>} data - a list of data objects
 * @returns {Term} an object with the keys of the data and the values as an array of the values of the data
 */
function reduceDataToObject(data) {
  const dataObject = {};
  data.forEach((record) => {
    Object.keys(record).forEach((variable) => {
      if (!dataObject[variable]) {
        dataObject[variable] = [];
      }
      dataObject[variable] = dataObject[variable].concat(record[variable]);
    });
  });
  return dataObject;
}

export default QueryResultList;
