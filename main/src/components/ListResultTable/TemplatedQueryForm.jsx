import {AutocompleteInput, required, SaveButton, SimpleForm, Toolbar, useResourceDefinition} from "react-admin";
import DoneIcon from '@mui/icons-material/Done';
import {Component, useEffect, useState} from "react";
import PropTypes from "prop-types";
import CustomQueryEditButton from "../CustomQueryEditor/customQueryEditButton";

const MyToolbar = () => (
  <Toolbar>
    <SaveButton icon={<DoneIcon/>} label="Query"/>
  </Toolbar>
);

/**
 * A custom form to set/choose values for variables for a templated query before that query is executed
 * @param {object} props - the props passed down to the component
 * @returns {Component} the templated query form component
 */
const TemplatedQueryForm = (props) => {
  const {
    variableOptions,
    onSubmit,
    submitted,
    searchPar,
    resource,
  } = props;

  const resourceDef = useResourceDefinition();

  const [selectedVariables, setSelectedVariables] = useState({});

  useEffect(() => {
    if (submitted) {
      onSubmit(searchPar);
    }
  }, [submitted]);

  useEffect(() => {
    const storedSelection = localStorage.getItem(`selectedVariables_${resource}`);
    if (storedSelection) {
      setSelectedVariables(JSON.parse(storedSelection));
    }
  }, [resource]);

  const handleVariableSelectionChange = (name, value) => {
    const updatedValues = {...selectedVariables, [name]: value};
    setSelectedVariables(updatedValues);

    localStorage.setItem(`selectedVariables_${resource}`, JSON.stringify(updatedValues));
  };

  return (
    <SimpleForm toolbar={<MyToolbar/>} onSubmit={onSubmit}>
      {!!resourceDef.options && resourceDef.options.queryGroupId === 'cstm' &&
        <CustomQueryEditButton queryID={resourceDef.name}/>}
      {Object.entries(variableOptions).map(([name, options]) => (
        <AutocompleteInput
          key={name}
          source={name}
          name={name}
          label={name}
          validate={required()}
          fullWidth={true}
          choices={
            options.map((option) => ({
              id: option,
              name: option
            }))}
          value={selectedVariables[name]}
          onChange={(value) => {
            handleVariableSelectionChange(name, value)
          }}
        />
      ))}
    </SimpleForm>
  );
}

TemplatedQueryForm.propTypes = {
  variableOptions: PropTypes.object,
  onSubmit: PropTypes.func,
  resource: PropTypes.string.isRequired,
};

export default TemplatedQueryForm;
