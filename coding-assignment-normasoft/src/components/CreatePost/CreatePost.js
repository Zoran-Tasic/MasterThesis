import React, {Component} from 'react';
import {withRouter} from "react-router-dom";

class CreatePost extends Component {
    state = {
        newPost: {
            id: "",
            title: "",
            postDate: "",
            creatorUser: "",
            postTags: "",
            content: ""
        }
    }

    changeHandler = (event) => {
        let id = event.target.id;
        let newPostCopy = {...this.state.newPost};
        newPostCopy[id] = event.target.value;
        this.setState({ newPost: newPostCopy});
    }

    addNewPost = () => {
        this.props.addNewPostToState(this.state.newPost);
        this.props.history.push("/");
    }


    render() {
        return ( 
            <div className = "container">
                <div className = "row">
                    <div className = "col-10 offset-1">
                        <h2 className = "display-4 m-4">Create post</h2> 
                        <div className = "row">
                            <div className = "col-10 offset-1">
                                <input type = "text" 
                                    onChange = {this.changeHandler} 
                                    id = "id" placeholder = "id" 
                                    className = "form-control"/> 
                                <br/>
                                <input type = "text"
                                    onChange = {this.changeHandler}
                                    id = "title" placeholder = "title"
                                    className = "form-control"/> 
                                <br/>
                                <input type = "text"
                                    onChange = {this.changeHandler}
                                    id = "postDate" placeholder = "post date"
                                    className = "form-control"/> 
                                <br/>
                                <input type = "text"
                                    onChange = {this.changeHandler}
                                    id = "creatorUser" placeholder = "creator user"
                                    className = "form-control"/> <br/>
                                <input type = "email"
                                    onChange = {this.changeHandler}
                                    id = "postTags" placeholder = "post tags"
                                    className = "form-control"/> 
                                <br/>
                                <input type = "text"
                                    onChange = {this.changeHandler}
                                    id = "content" placeholder = "content"
                                    className = "form-control"/> 
                                <br/>
                                <button onClick = {this.addNewPost}
                                    className = "btn btn-primary form-control"> Save </button> 
                            </div> 
                        </div> 
                    </div> 
                </div> 
            </div>
        )
    }
}
export default withRouter(CreatePost);