import React, { useState, useEffect } from 'react';
import IconProvider from '../../../IconProvider/IconProvider';
import Button from '@mui/material/Button';
import TextField from '@mui/material/TextField';
import Card from '@mui/material/Card';
import { Typography } from '@mui/material';
import Box from '@mui/material/Box';

import configManager from '../../../configManager/configManager';
import { addResource, getResource } from './podStorageManager';
import { getDefaultSession } from "@inrupt/solid-client-authn-browser";

export default function SaveCustomToPod() {
    const session = getDefaultSession();

    const [saveErrorMessage, setSaveErrorMessage] = useState("");
    const [loadErrorMessage, setLoadErrorMessage] = useState("")
    const [saveSuccesMessage, setSaveSuccesMessage] = useState("")
    const [loadSuccesMessage, setLoadSuccesMessage] = useState("")
    const [defaultPodRoot, setDefaultPodRoot] = useState(false)
    const [loadPodUri, setLoadPodUri] = useState("")
    const [savePodUri, setSavePodUri] = useState("")

    const placeholderString = session.info.isLoggedIn ? "" : "Log in to connect to a pod."

    // Place holders for the textfields
    if (session.info.isLoggedIn) {
        if (!defaultPodRoot) {
            let podRoot = session.info.webId.replace('profile/card#me', 'customQueries/myQueries.json')
            setDefaultPodRoot(true)
            setLoadPodUri(podRoot)
            setSavePodUri(podRoot)
        }
    } else {
        if (defaultPodRoot) {
            setDefaultPodRoot(false)
            setLoadPodUri("")
            setSavePodUri("")
        }
    }

    // Prevent double clicking the buttons
    const [isDisabled, setIsDisabled] = useState(false);

    const preventDoubleClick = () => {
        // Disable button after click
        setIsDisabled(true);
        // Simulate operation, like an API call
        setTimeout(() => { setIsDisabled(false)}, 500);  
    };


    const handleLoad = async (event) => {
        event.preventDefault();
        preventDoubleClick();

        if (session.info.isLoggedIn) {
            const eventData = new FormData(event.currentTarget);
            const jsonData = Object.fromEntries(eventData.entries());
            const podUriLoad = jsonData.loadFrom

            try {
                const queries = await getResource(podUriLoad)
                configManager.addCustomQueriesToQueryList(queries)
                setLoadErrorMessage('')
                setLoadSuccesMessage("Successfully loaded the queries from the pod!")
            } catch (e) {
                setLoadSuccesMessage("")
                setLoadErrorMessage(e.message)
            }
        }
    }

    const handleSave = async (event) => {
        event.preventDefault();
        preventDoubleClick();

        if (session.info.isLoggedIn) {
            const eventData = new FormData(event.currentTarget);
            const jsonData = Object.fromEntries(eventData.entries());
            const podUriSave = jsonData.saveTo
            const customQueries = configManager.getCustomQueries();

            try{
                if (customQueries.length === 0) {
                    setSaveSuccesMessage('');
                    setSaveErrorMessage("You have no custom queries.")
                } 
                else {
                    setSaveErrorMessage("")
                    const dataTotTransmit = JSON.stringify(customQueries)
                   
                    await addResource(podUriSave, "application/json", dataTotTransmit);
                    setSaveSuccesMessage("Successfully saved you queries on the pod!")
                }
            } catch(e) {
                setSaveSuccesMessage('');
                setSaveErrorMessage(e.message);
            }

        }

    }

    return (
        <Card sx={{ marginTop: '16px', width: '100%' }}>
            <Typography sx={{ padding: '20px' }}>Load or save your custom queries to a pod. Be careful, saving your queries to the pod will overwrite all the queries on the pod.</Typography>
            <Card
                component="form"
                onSubmit={handleLoad}
                sx={{ padding: '16px', backgroundColor: 'transparent', boxShadow: 'none', width: '100%' }}
            >
                <Typography sx={{ color: 'red', fontWeight: 'bold' }}>{loadErrorMessage}</Typography>
                <Box sx={{ display: 'flex', alignItems: 'center', width: '100%' }}>
                    <Button
                        disabled={!session.info.isLoggedIn || isDisabled}
                        variant="outlined"
                        color="warning"
                        type="submit"
                        startIcon={isDisabled? <IconProvider.HourglassTopIcon/>:<IconProvider.CloudUploadIcon />}
                        sx={{ margin: '10px' }}
                    >
                      {isDisabled ? "Patience..." : "Load All"}  
                    </Button>

                    <Typography sx={{ width: '30px', marginRight: '10px' }}>
                        From:
                    </Typography>

                    <TextField
                        required
                        disabled={!session.info.isLoggedIn}
                        name="loadFrom"
                        placeholder={placeholderString}
                        value={loadPodUri}
                        onChange={(e) => setLoadPodUri(e.target.value)}
                        variant="outlined"
                        sx={{ flexGrow: 1, marginX: '15px' }}
                    />
                </Box>
                <Typography sx={{ color: 'green', fontWeight: 'bold' }}>{loadSuccesMessage}</Typography>
            </Card>



            <Card
                component="form"
                onSubmit={handleSave}
                sx={{ padding: '16px', backgroundColor: 'transparent', boxShadow: 'none', width: '100%' }}
            >
                <Typography sx={{ color: 'red', fontWeight: 'bold' }}>{saveErrorMessage}</Typography>
                <Box sx={{ display: 'flex', alignItems: 'center', width: '100%' }}>
                    <Button
                        disabled={!session.info.isLoggedIn || isDisabled}
                        variant="outlined"
                        color="success"
                        type="submit"
                        startIcon={isDisabled? <IconProvider.HourglassTopIcon/>:<IconProvider.CloudUploadIcon />}
                        sx={{ marginX: '10px' }}
                    >
                        {isDisabled ? "Patience..." : "Save All"}  
                    </Button>

                    <Typography sx={{ width: '30px', marginRight: '10px' }}>
                        To:
                    </Typography>

                    <TextField
                        required
                        disabled={!session.info.isLoggedIn}
                        name="saveTo"
                        placeholder={placeholderString}
                        value={savePodUri}
                        onChange={(e) => setSavePodUri(e.target.value)}
                        variant="outlined"
                        sx={{ flexGrow: 1, marginX: '15px' }}
                    />
                </Box>
                <Typography sx={{ color: 'green', fontWeight: 'bold' }}>{saveSuccesMessage}</Typography>
            </Card>
        </Card>
    )
}
