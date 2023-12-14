import { useResourceDefinitions } from "ra-core";
import { DashboardMenuItem } from "ra-ui-materialui";
import { Menu } from "react-admin";
import { ThemeProvider, createTheme } from "@mui/material";
import AddIcon from '@mui/icons-material/Add';
import { Component } from "react";

/**
 * A custom menu as defined in React Admin for selecting the query the user whishes to execute.
 * @returns {Component} the selection menu component
 */
function SelectionMenu() {
  const resources = useResourceDefinitions();
  return (
    <ThemeProvider theme={menuItemTheme}>
      <Menu>
        <DashboardMenuItem />
        {Object.keys(resources).map((id) => (
          <Menu.ResourceItem key={id} name={id} />
        ))}
        <Menu.Item to="/createquery" primaryText="Create new query" leftIcon={<AddIcon />}/>
      </Menu>
    </ThemeProvider>
  );
}

const menuItemTheme = createTheme({
  components: {
    MuiMenuItem: {
      styleOverrides: {
        root: {
          display: "inline-block",
          overflow: "hidden",
          textOverflow: "ellipsis",
          position: "relative",
          maxWidth: "240px",
          minWidth: "0",
          "& > *": {
            verticalAlign: "middle",
          },
          "&:hover": {
            overflow: "visible",
            minWidth: "fit-content"
          }
        },
      },
    }
  },
});

export default SelectionMenu;
