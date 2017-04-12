# Multi user blog

Multi user blog application in Python 2.7 using Google App Engine and Jinja.
Example: https://writing-about-nothing.appspot.com
Last update: 2017-04-12

## Features

  - Signup, login and logout systems
   -- Login using hash and salt, passwords doesn't save in database
  - Users can create, like and comment posts
   -- Users can't like own posts
  - Users can edit and delete their posts and comments
   -- Users can edit and delete own posts
  - One page for each post with its comments
  - Completely responsive
  - Blog don't use JavaScript or Ajax

## Components

  - Front page to list blog posts
  - Forms to submit posts and comments
  - Welcome page, after login, with user's posts listed
  - Page for each post

## Install

All details to install SDK google appengine and deploy application are found in https://cloud.google.com/appengine/docs/standard/python/

For safety reasons, in main.py, the varable SECRET must be determined before run blog locally or deploy blog to google clound

## License

This project is made available under an Apache license version 2.0. View details in LICENSE.txt file.
