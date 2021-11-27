import React, {Component} from 'react';
import {withRouter} from "react-router-dom";

class EditPost extends Component {

    state = {
        post: {
            id: "",
            title: "",
            postDate: "",
            creatorUser: "",
            postTags: "",
            content: ""
        }
    }

    componentDidMount() {
        const postForEdit = this.props.posts.filter(p => p.id == this.props.match.params.id)[0];
        this.setState({post: postForEdit})
    }

    changePost = (event) => {
        const copyOfPost = {...this.state.post};
        copyOfPost[event.target.id] = event.target.value;
        this.setState({post: copyOfPost});
    }

    editPost = () => {
        this.props.editPost(this.state.post);
        this.props.history.push("/");
    }

    render() {
        return ( 
            <div className = "container">
                <div className = "row">
                    <div className = "col-10 offset-1">
                        <h2 className = "display-4 m-4">Edit Post</h2> 
                        <div className = "row">
                            <div className = "col-10 offset-1">
                                <input onChange = {this.changePost} type = "text" id = "title" className = "form-control" value = {this.state.post.title}/> <br/>
                                <input onChange = {this.changePost} type = "text" id = "postDate" className = "form-control" value = {this.state.post.postDate}/> <br/>
                                <input onChange = {this.changePost} type = "text" id = "creatorUser" className = "form-control" value = {this.state.post.creatorUser}/> <br/>
                                <input onChange = {this.changePost} type = "text" id = "postTags" className = "form-control" value = {this.state.post.postTags}/> <br/>
                                <input onChange = {this.changePost} type = "text" id = "content" className = "form-control" value = {this.state.post.content}/> <br/>
                                <button onClick = {this.editPost} className = "form-control btn btn-info">Edit</button> 
                            </div> 
                        </div> 
                    </div> 
                </div> 
            </div>
        )
    }
}

export default withRouter(EditPost);