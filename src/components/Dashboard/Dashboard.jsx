import Card from '@mui/material/Card';
import CardContent from '@mui/material/CardContent';
import config from "../../config";
import {Title} from 'react-admin';
import PropTypes from 'prop-types';
import './Dashboard.css';

/**
 * This function returns a function that creates a dashboard with an introduction for <Admin>.
 * @param {object} props - This has one property `text` with the introduction text.
 * @returns {function(): *} - A function that creates a dashboard with an introduction for <Admin>.
 */
function Dashboard(props) {
  let {text} = props;

  text = text || 'You change this text via the config file.';

  return (
    <Card>
      <Title title={config.title}/>
      <CardContent>{text}</CardContent>
    </Card>
  );
}

Dashboard.propTypes = {
  text: PropTypes.string
};

export default Dashboard;
