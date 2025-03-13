import "./AboutDialog.css";
import { Component } from "react";
import CloseIcon from "@mui/icons-material/Close";
import { IconButton, Dialog, DialogTitle, DialogContent } from "@mui/material";

import version from "../../../version";

/**
 * 
 * @param {boolean} props.open - forwarded to Dialog open
 * @param {function} props.close - forwarded to Dialog onClose and the close button
 * @returns {Component}
 */
function AboutDialog(props) {
  return (
    <Dialog open={props.open} onClose={props.close} fullWidth maxWidth="sm">
      <DialogTitle sx={{ display: "flex", justifyContent: "space-between", alignItems: "center" }}>
        <div><a href="https://idlab.ugent.be/">IDLab</a> Generic Data Viewer</div>
        <IconButton onClick={props.close} size="small">
          <CloseIcon />
        </IconButton>
      </DialogTitle>
      <DialogContent>
        <p>Version: {version}</p>
        <p><a href="https://github.com/SolidLabResearch/generic-data-viewer-react-admin" target="_blank">Repository</a></p>
        <p>Powered by <a href="https://comunica.dev/" target="_blank">Comunica</a></p>
      </DialogContent>
    </Dialog>
  );
}

export default AboutDialog;
