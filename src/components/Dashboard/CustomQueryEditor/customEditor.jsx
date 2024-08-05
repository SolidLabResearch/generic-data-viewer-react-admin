import React, { useState, useEffect } from 'react';
import Card from '@mui/material/Card';
import CardContent from '@mui/material/CardContent';
import Button from '@mui/material/Button';
import TextField from '@mui/material/TextField';
import { CardActions, Typography } from '@mui/material';
import { useLocation, useNavigate } from 'react-router-dom';
import FormControlLabel from '@mui/material/FormControlLabel';
import Checkbox from '@mui/material/Checkbox';
import configManager from '../../../configManager/configManager';
import IconProvider from '../../../IconProvider/IconProvider';



export default function CustomEditor(props) {

  const location = useLocation();
  const navigate = useNavigate();
  const [formData, setFormData] = useState({
    name: '',
    description: '',
    source: '',
    queryString: '',
    comunicaContext: '',
    comunicaContextCheck: false,
    sourceIndexCheck: false,
    askQueryCheck: false,
    directVariablesCheck: false,
    indirectVariablesCheck: false,

  });

  const [showError, setShowError] = useState(false);

  const [parsingErrorComunica, setParsingErrorComunica] = useState(false);
  const [parsingErrorAsk, setParsingErrorAsk] = useState(false);
  const [parsingErrorTemplate, setParsingErrorTemplate] = useState(false);

  const defaultIndirectVariableQuery = "PREFIX schema: <http://schema.org/> \n\nSELECT DISTINCT ?obj WHERE \n{ \n\t?list \n\tschema:obj ?obj; \n}"
  const [indirectVariableSourceList, setIndirectVariableSourceList] = useState([defaultIndirectVariableQuery]);

  const defaultSparqlQuery = `SELECT ?s ?p ?o
WHERE {
  ?s ?p ?o
}`;
  const defaultSparqlQueryIndexSources = `PREFIX rdfs: <http://www.w3.org/2000/01/rdf-schema#>
SELECT ?source
WHERE {
  ?s rdfs:seeAlso ?source
}`;
  const defaultExtraComunicaContext = JSON.stringify({ "lenient": true }, null, 2);
  const defaultAskQueryDetails = JSON.stringify({ "trueText": "this displays when true.", "falseText": "this displays when false." }, null, 2);
  const defaultTemplateOptions = JSON.stringify(
    {
      "variables": {
        "variableOne": [
          "option1",
          "(etc...)"],
        "(etc...)": [
        ]
      }
    }, null, 5)

  const [editError, setEditError] = useState(false)

  useEffect(() => {
    try {
      let searchParams
      if (props.newQuery) {
        searchParams = new URLSearchParams(location.search);
      } else {
        const edittingQuery = configManager.getQueryById(props.id);
        searchParams = edittingQuery.searchParams;
      }
      const obj = {}
      searchParams.forEach((value, key) => {
        obj[key] = value
      })

      if (obj.indirectQueries){
        setIndirectVariableSourceList(JSON.parse(obj.indirectQueries))
      }

      setFormData(obj)

    } catch (error) {
      setEditError(true)
    }
  }, [location.search]);

  const handleSubmit = async (event) => {
    event.preventDefault();

    if (!parsingErrorComunica && !parsingErrorAsk && !parsingErrorTemplate) {
      setShowError(false)
      const formData = new FormData(event.currentTarget);
      const jsonData = Object.fromEntries(formData.entries());
      
      if (jsonData.indirectVariablesCheck){
        jsonData.indirectQueries = JSON.stringify(indirectVariableSourceList)
      }

      const searchParams = new URLSearchParams(jsonData);
      jsonData.searchParams = searchParams;

      if (props.newQuery) {
        navigate({ search: searchParams.toString() });

        configManager.addNewQueryGroup('cstm', 'Custom queries', 'EditNoteIcon');
        addQuery(jsonData);
      }
      else {
        const customQuery = configManager.getQueryById(props.id);
        updateQuery(jsonData, customQuery);
      }
    } else {
      setShowError(true)
    }
  };

  // These functions handle the changes of the user input in the input fields
  const handleChange = (event) => {
    const { name, value } = event.target;
    setFormData((prevFormData) => ({
      ...prevFormData,
      [name]: value,
    }));
  };

  const handleIndirectVariablesChange = (event, index) => {
    const newList = [...indirectVariableSourceList]
    newList[index] = event.target.value
    setIndirectVariableSourceList(newList)
  }

  const handleJSONparsing = (event, errorSetter) => {
    const { name, value } = event.target;
    errorSetter(false)

    let parsedValue;
    try {
      parsedValue = JSON.parse(value);
    } catch (error) {
      errorSetter(true)
      parsedValue = value;
    }

    setFormData((prevFormData) => ({
      ...prevFormData,
      [name]: parsedValue,
    }));
  };

  // These functions serve for a correct parsing of JSON content
  const ensureBoolean = (value) => value === 'on' || value === true;

  const parseAllObjectsToJSON = (dataWithStrings) => {

    const parsedObject = dataWithStrings;

    if (ensureBoolean(dataWithStrings.comunicaContextCheck)) {
      parsedObject.comunicaContext = JSON.parse(dataWithStrings.comunicaContext);

      if (!!dataWithStrings.source && dataWithStrings.source.trim() !== '')
        parsedObject.comunicaContext.sources = dataWithStrings.source.split(';').map(source => source.trim());

    } else if (!!dataWithStrings.source && dataWithStrings.source.trim() !== '') {
      parsedObject.comunicaContext = {
        sources: formData.source.split(';').map(source => source.trim())
      }
    }

    if (ensureBoolean(dataWithStrings.sourceIndexCheck)) {
      parsedObject.sourcesIndex = {
        url: parsedObject.indexSourceUrl,
        queryString: parsedObject.indexSourceQuery
      }
    }

    if (ensureBoolean(dataWithStrings.askQueryCheck)) {
      parsedObject.askQuery = JSON.parse(dataWithStrings.askQuery);
    }

    if (ensureBoolean(dataWithStrings.directVariablesCheck)) {

      const options = JSON.parse(dataWithStrings.templateOptions);

      if (options.variables) {
        parsedObject.variables = options.variables;
      }

      // This will serve for the extention of customizable query variables
      if (options.indirectVariables) {
        parsedObject.indirectVariables = options.indirectVariables;
      }


    }
    if (ensureBoolean(dataWithStrings.indirectVariablesCheck)) {
     // console.log(dataWithStrings)
      parsedObject.indirectVariables = {queryStrings : JSON.parse(dataWithStrings.indirectQueries) }
    }
    return parsedObject;
  }


  // These are the functions for the addition and removal of indirect variable input fields
  const handleIndirectSource = () => {
    setIndirectVariableSourceList([...indirectVariableSourceList, ""])
  }
  const handleIndirectSourceRemove = (index) => {
    const newList = [...indirectVariableSourceList];
    newList.splice(index, 1);
    setIndirectVariableSourceList(newList)
  }



  // These Functions are the submit functions for whether the creation or edit of a custom query
  const addQuery = (formData) => {
    const creationID = Date.now().toString();
    formData = parseAllObjectsToJSON(formData);

    console.log(formData)
    configManager.addQuery({
      ...formData,
      id: creationID,
      queryGroupId: "cstm",
      icon: "AutoAwesomeIcon",
    });
    navigate(`/${creationID}`)
  };

  const updateQuery = (formData, customQuery) => {
    formData = parseAllObjectsToJSON(formData);
    configManager.updateQuery({
      ...formData,
      id: customQuery.id,
      queryGroupId: customQuery.queryGroupId,
      icon: customQuery.icon
    });

    navigate(`/${customQuery.id}`)
  };



  return (
    <React.Fragment>
      <Card
        component="form"
        onSubmit={handleSubmit}
        sx={{ padding: '16px', marginTop: '16px', width: '100%' }}
      >
        <CardContent>

          {editError ? <Typography variant="h6" sx={{ fontWeight: 'bold', color: 'darkred' }}> Apologies, something went wrong with the loading of your data... </Typography> : null   /* This is a small work around an error that occurs with indirect variables. */}
          <Typography variant="h5" sx={{ fontWeight: 'bold' }}>{props.newQuery ? 'Custom Query Editor' : 'Edit'}</Typography>

          <Card sx={{ py: '10px', px: '20px', my: 2 }}>
            <Typography variant="h5" sx={{ mt: 2 }}> Basic Information</Typography>
            <div>
              <TextField
                required
                fullWidth
                name="name"
                //  id="outlined-required"
                label="Query name"
                placeholder="Custom query name"
                helperText="Give this custom query a name."
                variant="outlined"
                value={!!formData.name ? formData.name : ''}
                onChange={handleChange}
                sx={{ marginBottom: '16px' }}
              />

              <TextField
                required
                // id="outlined-multiline-flexible"
                label="Description"
                name="description"
                multiline
                fullWidth
                minRows={2}
                variant="outlined"
                helperText="Give a description for the query."
                placeholder="This is a custom query."
                value={!!formData.description ? formData.description : ''}
                onChange={handleChange}
                sx={{ marginBottom: '16px' }}
              />

              <TextField
                required
                //  id="outlined-multiline-flexible"
                label="SPARQL query"
                name="queryString"
                multiline
                fullWidth
                minRows={5}
                variant="outlined"
                helperText="Enter your SPARQL query here."
                placeholder={defaultSparqlQuery}
                value={!!formData.queryString ? formData.queryString : formData.queryString === '' ? '' : defaultSparqlQuery}
                onChange={handleChange}
                sx={{ marginBottom: '16px' }}
              />
            </div>
          </Card>

          <Card sx={{ py: '10px', px: '20px', my: 2 }}>

            <Typography variant="h5" sx={{ mt: 2 }}> Comunica Context</Typography>
            <div>
              <FormControlLabel
                control={<Checkbox
                  name='comunicaContextCheck'
                  checked={!!formData.comunicaContextCheck}
                  onChange={
                    () => {
                      setParsingErrorComunica(false);
                      setFormData((prevFormData) => ({
                        ...prevFormData,
                        'comunicaContextCheck': !formData.comunicaContextCheck,
                      }))
                    }
                  }

                />} label="Advanced Comunica Context Settings" />

            </div>
            <TextField
              required={!formData.sourceIndexCheck}
              fullWidth
              name="source"
              //   id="outlined-required"
              label="Data source(s)"
              placeholder="http://example.com/source1; http://example.com/source2"
              helperText="Give the source URL(s) for the query. Separate URLs with '; '."
              variant="outlined"
              value={!!formData.source ? formData.source : ''}
              onChange={handleChange}
              sx={{ marginBottom: '16px' }}
            />


            {formData.comunicaContextCheck &&
              <div>
                <TextField
                  required={ensureBoolean(formData.comunicaContextCheck)}
                  //  id="outlined-multiline-flexible"
                  label="Comunica context configuration"
                  name="comunicaContext"
                  multiline
                  fullWidth
                  error={parsingErrorComunica}
                  minRows={5}
                  variant="outlined"
                  helperText={`Write the extra configurations in JSON-format${parsingErrorComunica ? ' (Invalid Syntax)' : '.'}`}
                  value={!!formData.comunicaContext ? typeof formData.comunicaContext === 'object' ? JSON.stringify(formData.comunicaContext, null, 2) : formData.comunicaContext : formData.comunicaContext === '' ? '' : defaultExtraComunicaContext}
                  placeholder={defaultExtraComunicaContext}
                  onClick={(e) => handleJSONparsing(e, setParsingErrorComunica)}
                  onChange={(e) => handleJSONparsing(e, setParsingErrorComunica)}
                  sx={{ marginBottom: '16px' }}
                />
              </div>
            }
          </Card>

          <Card sx={{ py: '10px', px: '20px', my: 2 }}>
            <Typography variant="h5" sx={{ mt: 2 }}> Extra Options</Typography>
            <div>
              <FormControlLabel
                control={<Checkbox
                  name='sourceIndexCheck'
                  checked={!!formData.sourceIndexCheck}
                  onChange={
                    () => {
                      setFormData((prevFormData) => ({
                        ...prevFormData,
                        'sourceIndexCheck': !formData.sourceIndexCheck,
                      }))
                    }
                  }
                />} label="Sources from index file" />

              {formData.sourceIndexCheck &&
                <div>
                  <TextField
                    required={ensureBoolean(formData.sourceIndexCheck)}
                    fullWidth
                    name="indexSourceUrl"
                    //  id="outlined-required"
                    label="Index file URL"
                    placeholder="http://example.com/index"
                    helperText="Give the URL of the index file."
                    variant="outlined"
                    value={!!formData.indexSourceUrl ? formData.indexSourceUrl : ''}
                    onChange={handleChange}
                    sx={{ marginBottom: '16px' }}
                  />

                  <TextField
                    required={ensureBoolean(formData.sourceIndexCheck)}
                    // id="outlined-multiline-flexible"
                    label="SPARQL query"
                    name="indexSourceQuery"
                    multiline
                    fullWidth
                    minRows={5}
                    variant="outlined"
                    helperText="Give the SPARQL query to get the sources from the index file."
                    placeholder={defaultSparqlQueryIndexSources}
                    value={!!formData.indexSourceQuery ? formData.indexSourceQuery : formData.indexSourceQuery === '' ? '' : defaultSparqlQueryIndexSources}
                    onChange={handleChange}
                    sx={{ marginBottom: '16px' }}
                  />
                </div>
              }

              <FormControlLabel
                control={<Checkbox
                  name='askQueryCheck'
                  checked={!!formData.askQueryCheck}
                  onChange={
                    () => {
                      setParsingErrorAsk(false);
                      setFormData((prevFormData) => ({
                        ...prevFormData,
                        'askQueryCheck': !formData.askQueryCheck,
                      }))
                    }
                  }
                />} label="ASK query" />

              {formData.askQueryCheck &&
                <div>
                  <TextField
                    required={ensureBoolean(formData.askQueryCheck)}
                    //  id="outlined-multiline-flexible"
                    label="Creating an ask query"
                    name="askQuery"
                    error={parsingErrorAsk}
                    multiline
                    fullWidth
                    minRows={5}
                    variant="outlined"
                    helperText={`Write askQuery details in JSON-format${parsingErrorAsk ? ' (Invalid Syntax)' : '.'}`}
                    value={!!formData.askQuery ? typeof formData.askQuery === 'object' ? JSON.stringify(formData.askQuery, null, 2) : formData.askQuery : formData.askQuery === '' ? '' : defaultAskQueryDetails}
                    placeholder={defaultAskQueryDetails}
                    onClick={(e) => handleJSONparsing(e, setParsingErrorAsk)}
                    onChange={(e) => handleJSONparsing(e, setParsingErrorAsk)}
                    sx={{ marginBottom: '16px' }}
                  />
                </div>
              }
              <FormControlLabel
                control={<Checkbox
                  name='directVariablesCheck'
                  checked={!!formData.directVariablesCheck}
                  onChange={
                    () => {
                      setParsingErrorTemplate(false);
                      setFormData((prevFormData) => ({
                        ...prevFormData,
                        'directVariablesCheck': !formData.directVariablesCheck,
                      }))
                    }
                  }
                />} label="Direct Variables" />

              {formData.directVariablesCheck &&
                <div>
                  <TextField
                    required={ensureBoolean(formData.directVariablesCheck)}
                    // id="outlined-multiline-flexible"
                    label="Templated query options"
                    name="templateOptions"
                    error={parsingErrorTemplate}
                    multiline
                    fullWidth
                    minRows={5}
                    variant="outlined"
                    helperText={`Write the variables specification in JSON-format${parsingErrorTemplate ? ' (Invalid Syntax)' : '.'}`}
                    value={!!formData.templateOptions ? typeof formData.templateOptions === 'object' ? JSON.stringify(formData.templateOptions, null, 5) : formData.templateOptions : formData.templateOptions === '' ? '' : defaultTemplateOptions}
                    placeholder={defaultTemplateOptions}
                    onClick={(e) => handleJSONparsing(e, setParsingErrorTemplate)}
                    onChange={(e) => handleJSONparsing(e, setParsingErrorTemplate)}
                    sx={{ marginBottom: '16px' }}
                  />
                </div>
              }

              <FormControlLabel
                control={<Checkbox
                  name='indirectVariablesCheck'
                  checked={!!formData.indirectVariablesCheck}
                  onChange={
                    () => {
                      setParsingErrorTemplate(false);
                      setFormData((prevFormData) => ({
                        ...prevFormData,
                        'indirectVariablesCheck': !formData.indirectVariablesCheck,
                      }))
                    }
                  }
                />} label="Indirect Variables" />

              {formData.indirectVariablesCheck &&
                <div>

                 
                  {indirectVariableSourceList.map((sourceString, index) => (

                    <div key={index} style={{ position: 'relative'}}>

                    <TextField
                      required={ensureBoolean(formData.indirectVariablesCheck)}
                      // id="outlined-multiline-flexible"
                      label={`Query ${index + 1} for Indirect Variable`}
                      name="indirectQueries"
                      //error={parsingErrorTemplate}
                      multiline
                      fullWidth
                      minRows={5}
                      variant="outlined"
                      helperText={`Enter the ${index === 0 ? "1st" : index === 1 ? "2nd" : index+1+"th" } SPARQL query to retrieve the variables.`}
                      value={sourceString}
                      placeholder={defaultIndirectVariableQuery}
                      onChange={(e) => handleIndirectVariablesChange(e, index)}
                      sx={{ marginBottom: '16px' }}
                      />
                    
                    <Button variant="outlined" color='error' onClick={() => handleIndirectSourceRemove(index)} type="button" disabled={indirectVariableSourceList.length <= 1}
                      style={{ 
                        position: 'absolute', 
                        top: '15px', 
                        right: '8px', 
                        padding: '8px', 
                        minWidth: 'auto', 
                        display: 'flex', 
                        alignItems: 'center', 
                        justifyContent: 'center' 
                      }}

                      > <IconProvider.DeleteIcon /> </Button>

                   

                      </div>

                  ))}
                   <Button variant="outlined" onClick={handleIndirectSource} type="button" startIcon={<IconProvider.AddIcon />}>Add another query</Button>
                </div>}

            </div>
          </Card>
        </CardContent>
        {showError && (
          <Typography variant="body2" sx={{ color: 'red', mb: '10px' }}>
            Invalid Query. Check the JSON-Syntax
          </Typography>
        )}
        <CardActions>
          <Button variant="contained" type="submit" startIcon={props.newQuery ? <IconProvider.AddIcon /> : <IconProvider.SaveAsIcon />}>{props.newQuery ? 'Create Query' : 'Save Changes'}</Button>
          {props.newQuery ? null : <Button variant="outlined" color='error' onClick={() => { navigate(`/${props.id}/`) }} startIcon={<IconProvider.CloseIcon />}>{'Cancel'}</Button>}

        </CardActions>
      </Card>

    </React.Fragment>
  )
}





