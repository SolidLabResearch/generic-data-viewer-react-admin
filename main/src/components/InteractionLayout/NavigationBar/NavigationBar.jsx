import { AppBar, TitlePortal, useRefresh } from "react-admin";
import "./NavigationBar.css";
import AuthenticationMenu from "../AuthenticationMenu/AuthenticationMenu";
import { Component, useState } from "react";
import CleaningServicesIcon from '@mui/icons-material/CleaningServices';
import { IconButton } from '@mui/material';
import { Tooltip } from '@mui/material';
import HelpIcon from '@mui/icons-material/Help';
import AboutDialog from "./AboutDialog";

import configManager from "../../../configManager/configManager";
import comunicaEngineWrapper from "../../../comunicaEngineWrapper/comunicaEngineWrapper";

function AboutButton(props) {
  return (
    <Tooltip title="About">
      <IconButton color="inherit" onClick={props.click}>
        <HelpIcon />
      </IconButton>
    </Tooltip>
  )
}

function InvalidateButton() {
  const refresh = useRefresh();
  const handleClick = () => {
    comunicaEngineWrapper.reset();
    setTimeout(refresh, 2000);
  }
  return (
    <Tooltip title="Clean Query Cache">
      <IconButton color="inherit" onClick={handleClick}>
        <CleaningServicesIcon />
      </IconButton>
    </Tooltip>
  )  
}

/**
 * 
 * @param {object} props - the props passed down to the component 
 * @returns {Component} custom AppBar as defined by react-admin
 */
function NavigationBar(props) {
  const config = configManager.getConfig();

  const [aboutOpen, setAboutOpen] = useState(false);

  const handleAboutOpen = () => setAboutOpen(true);
  const handleAboutClose = () => setAboutOpen(false);

  return (
    <>
      <AppBar {...props} userMenu={<AuthenticationMenu />}>
        <img
          id="app-logo"
          src={config.logoLocation}
          alt="Web application logo"
        ></img>
        <TitlePortal/>
        <AboutButton click={handleAboutOpen} />
        <InvalidateButton/>
      </AppBar>
      <AboutDialog open={aboutOpen} close={handleAboutClose} />
    </>
  );
}

export default NavigationBar;
