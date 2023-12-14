import { Component, useEffect, useState } from "react";
import { ExportButton, TopToolbar, useListContext } from "react-admin";
import Time from "./Time";
import config from "../../config";
import "./ActionBar.css";
import {
  Grid,
  IconButton,
  Paper,
  Table,
  TableBody,
  TableCell,
  TableContainer,
  TableHead,
  TableRow,
  Tooltip,
} from "@mui/material";
import InfoIcon from "@mui/icons-material/Info";
import SourceAuthenticationIcon from "./SourceAuthenticationIcon/SourceAuthenticationIcon";
import SourceFetchStatusIcon from "./SourceFetchStatusIcon/SourceFetchStatusIcon";
import QueryEditButton from "./QueryEditButton.jsx";

/**
 *
 * @returns {Component} custom action bar as defined by react-admin
 */
function ActionBar() {
  const { total, isLoading, perPage, resource } = useListContext();
  const [time, setTime] = useState(0);
  const [sourceInfoOpen, setSourceInfoOpen] = useState(false);

  const context = config.queries.filter((query) => query.id === resource)[0]
    .comunicaContext;

  const sources = context.sources;
  useEffect(() => {
    if (isLoading) {
      setTime(0);
    }
  }, [isLoading]);

  useEffect(() => {
    let intervalId;
    if (isLoading) {
      intervalId = setInterval(() => setTime(time + 1), 10);
    }
    return () => clearInterval(intervalId);
  }, [time, isLoading]);

  const resultCount = total <= perPage ? total : perPage;

  return (
    <Grid container direction="row" width={"100%"} rowSpacing={1}>
      <Grid item height={"fit-content"} width={"100%"}>
        <TopToolbar style={{ width: "100%", height: "fit-content" }}>
          <div style={{ flex: "1" }}></div>
          <div className="query-information">
            <div className="information-box">
              {isLoading && <strong>Loading: </strong>}
              {!isLoading && <strong>Loaded: </strong>}
              <span>{resultCount} results</span>
            </div>
            <div className="information-box">
              {isLoading && <strong>Runtime: </strong>}
              {!isLoading && <strong>Finished in: </strong>}
              <Time time={time} showMilliseconds={config.showMilliseconds} />
            </div>
            <div className="information-box">
              <strong>Sources: </strong>
              <span>{sources.length}</span>
              <Tooltip title="Sources info">
                <IconButton
                  size="small"
                  sx={{ padding: "0px", marginLeft: "5px" }}
                  onClick={() => setSourceInfoOpen(!sourceInfoOpen)}
                >
                  <InfoIcon fontSize="small" />
                </IconButton>
              </Tooltip>
            </div>
          </div>
          <div className="action-box">
            <QueryEditButton/>
            <ExportButton disabled={total === 0 || isLoading} />
          </div>
        </TopToolbar>
      </Grid>
      {sourceInfoOpen && (
        <Grid item width={"100%"}>
          <TableContainer
            sx={{ width: "100%", marginBottom: "10px", maxHeight: "200px" }}
            component={Paper}
          >
            <Table size="small" >
              <TableHead>
                <TableRow>
                  <TableCell>Source</TableCell>
                  <TableCell>Authentication needed</TableCell>
                  <TableCell>Fetch status</TableCell>
                </TableRow>
              </TableHead>
              <TableBody>
                {sources.map((source, index) => (
                  <TableRow key={index}>
                    <TableCell>{source}</TableCell>
                    <TableCell>
                      <SourceAuthenticationIcon source={source} />
                    </TableCell>
                    <TableCell>
                      <SourceFetchStatusIcon proxyUrl={config.httpProxy} context={context} source={source} />
                    </TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          </TableContainer>
        </Grid>
      )}
    </Grid>
  );
}

export default ActionBar;
