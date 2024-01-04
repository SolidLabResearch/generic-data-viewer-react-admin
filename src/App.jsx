import "./App.css";
import { Admin, Resource } from "react-admin";
import SparqlDataProvider from "./dataProvider/SparqlDataProvider";
import config from "./config";
import { Component, useEffect, useState } from "react";
import {
  getDefaultSession,
  handleIncomingRedirect,
} from "@inrupt/solid-client-authn-browser";
import authenticationProvider from "./authenticationProvider/authenticationProvider";
import SolidLoginForm from "./components/LoginPage/LoginPage";
import {QueryClient} from "react-query";
import Dashboard from "./components/Dashboard/Dashboard";
import InteractionLayout from "./components/InteractionLayout/InteractionLayout";
import TemplatedQueryForm from "./components/ListResultTable/TemplatedQueryForm.jsx";

const queryClient = new QueryClient({
  defaultOptions: {
    queries: {
      retry: false,
    },
  },
});

/**
 * @returns {Component} the main component of the application
 */
function App() {
  const session = getDefaultSession();
  const [loggedIn, setLoggedIn] = useState();

  useEffect(() => {
    const root = document.documentElement;
    root.style.setProperty("--text-color", config.textColor);
  }, []);

  useEffect(() => {
    session.onLogin(() => setLoggedIn(true));
    session.onLogout(() => setLoggedIn(false));

    // In this function we don't use await because inside a React Effect it causes linting warnings and according to several sources on the Web it is not recommended.
    // https://ultimatecourses.com/blog/using-async-await-inside-react-use-effect-hook
    // https://www.thisdot.co/blog/async-code-in-useeffect-is-dangerous-how-do-we-deal-with-it/
    handleIncomingRedirect({ restorePreviousSession: true }).then((info) => {
      if (info) {
        const status = info.isLoggedIn;
        if (status !== loggedIn) {
          setLoggedIn(status);
        }
      }
    });
  });
  return (
    <Admin
      queryClient={queryClient}
      dataProvider={SparqlDataProvider}
      layout={InteractionLayout}
      authProvider={authenticationProvider}
      loginPage={SolidLoginForm}
      requireAuth={false}
      dashboard={() => {
        return Dashboard({text: config.introductionText})
      }}
    >
      {config.queries.map((query) => {
        return (
          <Resource
            key={query.id}
            name={query.id}
            options={{ label: query.name }}
            list={TemplatedQueryForm}
          />
        );
      })}
    </Admin>
  );
}

export default App;
