import {required, SimpleForm, TextInput} from "react-admin";
import config from "../../config";
import {useEffect, useState} from "react";

/**
 * A query editor form that contains multiple input fields to create a new query or edit an existing query
 * and sync those changes to a pod
 * @returns {Component} the query editor component
 */
function QueryEditor(props) {

    let {newQuery} = props

    const [queryText, setQueryText] = useState()

    let query;
    if (!newQuery) {
        query = config.queries.filter(
            (query) => query.id === props.id
        )[0];
    }

    useEffect(() => {
        if (query) {
            fetch(`${config.queryFolder}${query.queryLocation}`)
                .then((response) =>
                response.text())
                .then((text) =>
                setQueryText(text));
        }
    }, [])

    const onSubmit = (data) => {
        if (newQuery) {
            // Create new query
        } else {
            // Edit existing query
        }
    }

    return (
        <SimpleForm onSubmit={onSubmit}>
            <TextInput source="id" name={"Query ID"} validate={[required()]} defaultValue={query ? query.id : undefined}/>
            <TextInput source="name" name={"Name"} validate={[required()]} defaultValue={query ? query.name : undefined}/>
            <TextInput source="description" name={"Description"} defaultValue={query ? query.description : undefined}/>
            <TextInput source="query" multiline={true} name={"Query"} defaultValue={queryText}/>
            ${queryText}
            <TextInput source="truetext" multiline={true} name={"True text"} defaultValue={query ? (query.askQuery ? query.trueText : undefined) : undefined}/>
            <TextInput source="falsetext" multiline={true} name={"False text"} defaultValue={query ? (query.askQuery ? query.falseText : undefined) : undefined}/>
        </SimpleForm>
    )
}

export default QueryEditor;