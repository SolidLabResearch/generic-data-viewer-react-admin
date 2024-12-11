import {AutocompleteInput, required, SaveButton, SimpleForm, Toolbar, useResourceDefinition} from "react-admin";
import DoneIcon from '@mui/icons-material/Done';
import {Component, useEffect} from "react";
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
  } = props;

  const resourceDef = useResourceDefinition();

  useEffect(() => {
    if (submitted) {
      onSubmit(searchPar);
    }
  }, [submitted])

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
        />
      ))}
    </SimpleForm>
  );
}

TemplatedQueryForm.propTypes = {
  variableOptions: PropTypes.object,
  onSubmit: PropTypes.func,
};

export default TemplatedQueryForm;
