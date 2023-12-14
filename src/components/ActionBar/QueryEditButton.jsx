import {Button} from "react-admin";
import EditIcon from "@mui/icons-material/Edit";
import {useNavigate} from "react-router-dom";

/**
 * A custom button to add to the action bar of the query result list to edit the query's properties
 * @returns {Component} the edit query button component
 */
function QueryEditButton(props) {

    const navigate = useNavigate();

    const onClick = () => {
        navigate("edit")
    }

    return (
        <Button onClick={onClick}>
            <EditIcon/>
            Edit
        </Button>
    )
}

export default QueryEditButton;