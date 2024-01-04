import React, {useState} from 'react';
import ListResultTable from "./ListResultTable.jsx";
import {SelectInput, SimpleForm, useResourceContext} from "react-admin";
import {useLocation} from 'react-router-dom';

import config from "../../config";

/**
 * A custom form to set/choose values for variables for a templated query before that query is executed
 * @returns {Component} the templated query form component
 */
const TemplatedQueryForm = (props) => {
    const resource = useResourceContext();

    const query = config.queries.filter(
        (query) => query.id === resource
    )[0];

    if (!query.variables) {
        return <ListResultTable {...props}/>;
    }

    const location = useLocation();
    const queryParams = new URLSearchParams(location.search);

    const urlVariables = {}
    for (const variableName of Object.keys(query.variables)) {
        if (queryParams.has(variableName)) {
            urlVariables[variableName] = queryParams.get(variableName)
        }
    }
    const [variables, setVariables] = useState(urlVariables);

    const [redirectToList, setRedirectToList] = useState(Object.keys(urlVariables).length === Object.keys(query.variables).length)
    if (redirectToList) {
        return <ListResultTable {...props} variables={variables}/>;
    }

    const onSubmit = (data) => {
        setVariables(data)
        setRedirectToList(true);
    }

    return (
        <SimpleForm onSubmit={onSubmit}>
            {Object.entries(query.variables).map(([name, options]) => (
                <SelectInput key={name} source={name} name={name} choices={
                    options.map((option) => ({
                        id: option,
                        name: option
                    }))
                }/>
            ))}
        </SimpleForm>
    )
}

export default TemplatedQueryForm;