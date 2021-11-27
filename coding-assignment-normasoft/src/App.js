import React, {Component} from 'react';
import Header from "./components/Header/Header";
import {Route, BrowserRouter, Switch} from "react-router-dom";
import PostsTable from "./components/PostsTable/PostsTable";
import CreatePost from "./components/CreatePost/CreatePost";
import EditTable from "./components/EditTable/EditTable";
import EditPost from "./components/EditPost/EditPost";

class App extends Component {
    //to do implement redux-state managment
    //Dummy API models:
    //PostPreview vs state.posts:
    //id=id, image=title, publishDate=postDate, owner=creatorUser, tags=postTags, text=content, likes=none
    state = {
        posts: [
            {id: 1, title: "FirstPost", postDate: "21.11.2021.", creatorUser: "John Doe", postTags: "dogs, human, beach", content:"LoremIpsumDolores..."},
            {id: 2, title: "AnotherPost", postDate: "01.06.2020.", creatorUser: "Adam Smith", postTags: "pet, cat", content:"Once upon a time lived a princess..."}
        ]
    }

    addNewPostToState = (post) => {
        this.setState({
            posts: [...this.state.posts, post]
        })
    }

    deletePost = (id) => {
        const postsCopy = [...this.state.posts];
        const newCopyPosts = postsCopy.filter(post => post.id !== id);
        this.setState({posts: newCopyPosts});

    }

    editPost = (p) => {
        const copyPosts = [...this.state.posts];
        let postPossition = copyPosts.map(post => post.id).indexOf(p.id)
        copyPosts[postPossition] = p;
        this.setState({posts: copyPosts})
    }

    render() {
        return (
            <BrowserRouter>
                <Header/>
                <Route path = "/" exact>
                    <PostsTable posts = {this.state.posts}/> 
                </Route>
                <Route path = "/create">
                    <CreatePost addNewPostToState = {this.addNewPostToState}/> 
                </Route>
                <Switch>
                    <Route path = "/edit/:id">
                        <EditPost posts = {this.state.posts} editPost = {this.editPost}/> 
                    </Route> 
                    <Route path = "/edit">
                        <EditTable posts = {this.state.posts} deletePost = {this.deletePost}/> 
                    </Route>
                </Switch> 
            </BrowserRouter >
        )
    }
}

export default App;