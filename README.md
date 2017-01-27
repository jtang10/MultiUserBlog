# Multi-User Blog
##
### Overview

This is the 3rd project in Udacity Full Stack Nanodegree, which implements the backend of a multi-user blog. The blog is implemented by Google App Engine and has the following basic functions:

 * Users can signup, login and logout the website. Cookie and password are properly hashed for security.
 * Users can post blogs on the website. They can also edit or delete the blogs of their own.
 * Users can like and comment on other users' blog. 

### Things Learned

The entire project is built on Google App Engine platform. Python is the main language used. In the backend handler, more OOP concepts are learned. In the process of building up webpages, Jinja2 templates are used and basic HTML and HTTP concept such as  `<form>` and get and post are learned. Need to learn more about submitting multiple forms in a single webpage and guess that is something I can learn through Javascript.

### Configuration

The following tutorial will go through the main steps of trying this website. For detailed guide on how to create and deploy, please follow [Guide on Udacity](https://drive.google.com/file/d/0Byu3UemwRffDc21qd3duLW9LMm8/view)
 1. Install Python. Python 2.7 or above is required.
 2. Install Google Cloud SDK. 
 3. Install App Engine Python extension.
 4. Download my project from [here](https://github.com/jtang10/MultiUserBlog.git).
 5. navigate to the project folder and type in `dev_appserver.py .` and access http://localhost:8080/blog through the browser. You can also acces it at.
