import {ListBase, Loading, useListController,} from "react-admin";
import PropTypes from "prop-types";
import {Component, useEffect} from "react";
import QueryResultList from "./QueryResultList/QueryResultList";

import {useLocation, useNavigate} from 'react-router-dom'

/**
 * @param {object} props - the props passed down to the component
 * @returns {Component} custom List as defined by react-admin which either shows a loading indicator or the query results
 */
function ListResultTable(props) {
  const {
    debounce,
    disableSyncWithLocation,
    exporter,
    filter,
    filterDefaultValues,
    perPage,
    resource,
    sort,
    variables,
    ...rest
  } = props;

  const location = useLocation();
  const navigate = useNavigate();

  useEffect(() => {
    if (variables) {
      const queryParams = new URLSearchParams(location.search);

      for (const [variableName, variableValue] of Object.entries(variables)) {
        queryParams.set(variableName, variableValue)
      }

      navigate(
        `?${queryParams.toString()}`
      );
    }
  }, [location.search, navigate]);

  const {isLoading} = useListController({
    queryOptions: {
      meta: {
        variables: variables
      }
    }
  });

  return (
    <ListBase
      debounce={debounce}
      disableAuthentication={true} // A query can go over multiple sources, some of which he doesn't need authentication. Thus we don't know which need authentication and which do not. We still have authentication with this being true.
      disableSyncWithLocation={disableSyncWithLocation}
      exporter={exporter}
      filter={filter}
      filterDefaultValues={filterDefaultValues}
      perPage={perPage}
      queryOptions={{keepPreviousData: false}}
      resource={resource}
      sort={sort}
    >
      {isLoading && <Loading loadingSecondary={"The page is loading. Just a moment please."} />}
      {!isLoading && <QueryResultList {...rest} />}
    </ListBase>
  );
}

ListResultTable.propTypes = {
  debounce: PropTypes.number,
  disableAuthentication: PropTypes.bool,
  disableSyncWithLocation: PropTypes.bool,
  exporter: PropTypes.func,
  filter: PropTypes.object,
  filterDefaultValues: PropTypes.object,
  perPage: PropTypes.number,
  queryOptions: PropTypes.object,
  resource: PropTypes.string,
  sort: PropTypes.object,
  variables: PropTypes.object,
};

export default ListResultTable;
