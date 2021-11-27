import React from 'react';
import {Link} from 'react-router-dom';


const Post = ({post, edit, deletePost}) => {
    const actionButtons = edit ? ( 
        <>
            <td> 
                <button onClick = {() => {deletePost(post.id)}} className = "btn btn-danger">Delete</button>
            </td>
            <td> 
                <Link to = {"/edit/" + post.id} className = "btn btn-warning">Edit</Link> 
            </td> 
        </>
        ) : null;
    return ( 
        <tr>
            <td> {post.id} </td> 
            <td> {post.title} </td> 
            <td> {post.postDate} </td> 
            <td> {post.creatorUser} </td> 
            <td> {post.postTags} </td> 
            <td> {post.content} </td>   
            {actionButtons} 
        </tr>
    )
}

export default Post;