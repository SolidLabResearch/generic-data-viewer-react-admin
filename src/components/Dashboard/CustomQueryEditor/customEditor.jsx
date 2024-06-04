import React, { useState, useEffect } from 'react';
import Dialog from '@mui/material/Dialog';
import DialogTitle from '@mui/material/DialogTitle';
import Button from '@mui/material/Button';
import TextField from '@mui/material/TextField';
import DialogActions from '@mui/material/DialogActions';
import DialogContent from '@mui/material/DialogContent';
import DialogContentText from '@mui/material/DialogContentText';
import { QueryEngine } from "@comunica/query-sparql";

//import { useLocation, useNavigate } from 'react-router-dom';


import configManager from '../../../configManager/configManager';

import TableData from './tableData';

const myEngine = new QueryEngine();

export default function CustomEditor() {

  const [openEditor, setOpenEditor] = useState(false);
  const [showError, setShowError] = useState(false);
  const [isSubmitted, setIsSubmitted] = useState(false);

  const [showTable, setShowTable] = useState(false);

  const closeEditor = () => {
    setOpenEditor(false);
    setShowError(false);
  }

  //investigate state re-render? maybe send to dashboard instead of own component

  return (
    <React.Fragment>
      <Button variant="contained" onClick={
        () => { setOpenEditor(true) }}
        sx={{ margin: '10px' }}>
        Custom query

      </Button>
      {isSubmitted &&
        <Button variant="outlined" color={showTable ? "error" : "primary"} onClick={
          () => {
            setShowTable(!showTable);
          }}>
          {showTable ? "Hide Results" : "Show Results"}
        </Button>
      }

      <Dialog
        open={openEditor}
        onClose={closeEditor}
        maxWidth={'md'}
        fullWidth
        PaperProps={{
          component: 'form',
          onSubmit: async (event) => {
            event.preventDefault();
            const formData = new FormData(event.currentTarget);
            const jsonData = Object.fromEntries(formData.entries());

            // TODO: NEED A CHECK HERE TO SEE IF WE MAY SUBMIT (correct query)
            //  const data = await executeSPARQLQuery(jsonData.query, jsonData.source, setShowError)

            configManager.addNewQueryGroup('cstm', 'Custom queries', 'EditNoteIcon');
            addQuery(jsonData)



            setIsSubmitted(false)
            setShowTable(false)
            closeEditor();
            setIsSubmitted(true)
          },
        }}
      >
        <DialogTitle>Custom Query Editor</DialogTitle>
        <DialogContent>
          <DialogContentText sx={{ color: 'red', mb: '10px' }}>
            {showError ? 'Invalid Query. Check the URL and Query Syntax' : ''}
          </DialogContentText>

          <div>
            <TextField
              required
              fullWidth
              name='title'
              id="outlined-required"
              label="Query title "
              placeholder="Custom query name"
              helperText="Give this custom query a name"
              variant='outlined'
            />

            <TextField
              required
              id="outlined-multiline-flexible"
              label="Description"
              name='description'
              multiline
              fullWidth
              minRows={2}
              variant='outlined'
              helperText="Give a description for the query"
              placeholder={`This is a custom query.`}
            />
          </div>

          <div>
            <TextField
              required
              fullWidth
              name='source'
              id="outlined-required"
              label="Data Source "
              placeholder="http://examplesource.org ; source2"
              helperText="Give the source Url('s) for the query. You can add more than one source separated with ' ; '"
              variant='outlined'
            />
          </div>

          <div>
            <TextField
              required
              id="outlined-multiline-flexible"
              label="Custom Query"
              name='query'
              multiline
              fullWidth
              minRows={5}
              variant='outlined'
              helperText="Give the SPARQL query"
              placeholder={`SELECT ?s ?p ?o \nWHERE { \n\t?s ?p ?o \n}`}
            />
          </div>
        </DialogContent>

        <DialogActions>
          <Button onClick={closeEditor}>Cancel</Button>
          <Button variant="contained" type="submit">Submit Query</Button>
        </DialogActions>
      </Dialog>

      {/* {showTable && <TableData data={customQueryData} title={customQueryJSON.title} />} */}

    </React.Fragment>
  )
}

// Temporary bindingstream
async function executeSPARQLQuery(query, dataSource, setShowError) {
  const resultingObjects = [];
  try {
    const bindingsStream = await myEngine.queryBindings(query, {
      sources: dataSource.split(';').map(source => source.trim())
    });

    bindingsStream.on('data', (binding) => {
      resultingObjects.push(JSON.parse(binding.toString()));
    });
  } catch (error) {
    setShowError(true);
    throw new Error(`Error executing SPARQL query: ${error.message}`);
  }
  return resultingObjects;
};


//Mock query
const addQuery = (formData) => {
  configManager.addQuery({
    id: Date.now().toString(),
    queryGroupId: "cstm",
    icon: "AutoAwesomeIcon",
    queryString: formData.query,
    name: formData.title,
    description: formData.description,
    comunicaContext: {
      sources: formData.source.split(';').map(source => source.trim())
    },

    // Location for testing purposes, delete after it works with the querystring
   // queryLocation: "components.rq"
  });
};
