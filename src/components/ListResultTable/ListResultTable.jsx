import {ListBase, Loading, useListController,} from "react-admin";
import PropTypes from "prop-types";
import {Component} from "react";
import QueryResultList from "./QueryResultList/QueryResultList";

import configManager from "../../configManager/configManager";

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

  const {isLoading} = useListController({
    queryOptions: {
      meta: {
        variables: variables
      }
    }
  });

  const query = configManager.getQueryWorkingCopyById(resource);

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
      {!isLoading && <QueryResultList resource={resource} { ...rest } />}
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
  resource: PropTypes.string.isRequired,
  sort: PropTypes.object,
  variables: PropTypes.object.isRequired
};

export default ListResultTable;
