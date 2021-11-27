import React from 'react';
import {Link, NavLink} from "react-router-dom";
import "./Header.css";

const Header = () => {
    return ( 
        <nav className = "navbar navbar-expand-lg navbar-light bg-light">
            <Link to = "/" className = "navbar-brand"> Coding asignment NormaSoft </Link>  
            <ul className = "navbar-nav ml-auto">
                <NavLink to = "/" exact className = "nav-link" activeClassName = {"activeLink"}>Posts</NavLink> 
                <NavLink to = "/create" className = "nav-link" activeClassName = {"activeLink"}>Create post</NavLink> 
                <NavLink to = "/edit" className = "nav-link" activeClassName = {"activeLink"}>Edit / Delete</NavLink>  
            </ul>
        </nav>
    )
}

export default Header;