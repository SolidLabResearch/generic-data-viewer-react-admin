import { Component, useEffect, useState } from "react";
import { Datagrid, ListView, Title, useListContext, useResourceDefinition } from "react-admin";
import ActionBar from "../../ActionBar/ActionBar";
import GenericField from "../../../representationProvider/GenericField";
import { Term } from "sparqljs";
import TableHeader from "./TableHeader/TableHeader";
import Button from '@mui/material/Button';
import SearchOffIcon from '@mui/icons-material/SearchOff';
import { SvgIcon, Box, Typography } from "@mui/material";
import PropTypes from "prop-types";

import configManager from "../../../configManager/configManager";

/**
 * @param {object} props - the props passed down to the component
 * @returns {Component} custom ListViewer as defined by react-admin containing the results of the query with each variable its generic field. 
 */
function QueryResultList(props) {
  const queryTitle = useResourceDefinition().options.label;
  const { data } = useListContext(props);
  const { resource, changeVariables, submitted} = props;
  const [values, setValues] = useState(undefined);
  useEffect(() => {
    if (data && data.length > 0) {
      const setData = reduceDataToObject(data);
      delete setData.id;
      setValues(setData);
    }
  }, [data]);

  const config = configManager.getConfig();
  const query = configManager.getQueryWorkingCopyById(resource);

  return (
    <div style={{ paddingLeft: '20px' , paddingRight: '10px' }}>
      <Title title={config.title} />
      
      {submitted && <Aside changeVariables={changeVariables}/> /*  Adding button to make a new query - top left corner */ } 
      <Typography fontSize={"2rem"} mt={2} > {queryTitle} </Typography>
      {values ?(
        <ListView title=" " actions={<ActionBar />} {...props} >
            <Datagrid header={<TableHeader query={query}/>} bulkActionButtons={false}>
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
          </ListView>
        ): 
          <NoValuesDisplay/>
      }
    </div>
  );
}

QueryResultList.propTypes = {
  changeVariables: PropTypes.func.isRequired,
  submitted: PropTypes.bool.isRequired
};

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

const Aside = (props) => {
  const {changeVariables} = props;
  return(
    <div>
      <Button variant="contained" onClick={changeVariables}>Change Variables</Button>
    </div>
)}

const NoValuesDisplay = () => {
  return(
    <div>
      <Box display="flex" alignItems="center" sx={{m:3}}>
        <SvgIcon component={SearchOffIcon} />
        <span>The result list is empty.</span>
      </Box>
    </div>
    
  )
}
  
export default QueryResultList;
