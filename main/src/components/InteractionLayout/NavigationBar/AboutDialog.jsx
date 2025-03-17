import { Component } from "react";
import CloseIcon from "@mui/icons-material/Close";
import { IconButton, Dialog, DialogTitle, DialogContent, DialogContentText } from "@mui/material";

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
        <DialogContentText>
          <p>Version: {version}</p>
          <p>Questions? Remarks?
            Please create an issue at our <a href="https://github.com/SolidLabResearch/generic-data-viewer-react-admin" target="_blank">Repository</a><br />
            or mail to <a href="mailto:ben.demeester@ugent.be" target="_blank">ben.demeester@ugent.be</a>.</p>
          <p>Powered by <a href="https://comunica.dev/" target="_blank">Comunica</a> and <a href="https://marmelab.com/react-admin/" target="_blank">React-Admin</a>.</p>
          <p>Initial development funded by <a href="https://ontodeside.eu/" target="_blank">Onto-DESIDE</a> and <a href="https://solidlab.be/" target="_blank">SolidLab</a>.</p>
        </DialogContentText>
      </DialogContent>
    </Dialog>
  );
}

export default AboutDialog;
