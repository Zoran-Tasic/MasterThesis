import React from "react";
import Post from "../Post/Post";

const PostsTable = ({posts}) => {

    const allPosts = posts.map(post => {
            return ( 
                <Post post = {post} key = {post.id}/>
            )
        }
    )
    return ( 
    <div className = "container">
        <div className = "row">
            <div className = "col-10 offset-1">
                <h3 className = "display-4 m-4">All posts</h3> 
                <div className = "row">
                    <div className = "col-10 offset-1">
                        <table className = "table">
                            <thead className = "float-left" >
                                <tr>
                                    <th>Id</th> 
                                    <th>Title</th > 
                                    <th>Post date</th> 
                                    <th>Creator user</th> 
                                    <th>Post tags</th>
                                    <th>Brief contents</th>
                                </tr> 
                            <tbody> 
                                {allPosts} 
                            </tbody> 
                            </thead> 
                        </table> 
                    </div> 
                </div> 
            </div> 
        </div> 
    </div>
    );
};

export default PostsTable;