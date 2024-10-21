# Strava Activity Tool
CLI tool to help automate common Strava tasks.

# Table Of Contents
- [Overview](#overview)
- [Setup](#setup)
- [Commands](#commands)
- [Internals](#internals)

# Overview
This tool uses the Strava API to automate common tasks:

- [Updating multiple activities at once](#command---update-activities)

See the [setup instructions](#setup) to get started.

# Setup
1. A Python virtual environment is used manage Python dependencies. The [Pipenv](https://pipenv.pypa.io/en/latest/) tool is used. To setup the project run:
   ```shell
   pipenv install
   ```
   Then run `pipenv shell` and run all the following commands and any `strava_tool/main.py` invocations in that shell.
2. Make a Strava API application. This can be done on this [Strava page](https://www.strava.com/settings/api). Set the redirect URL to `localhost`. You will need to know the client ID and client secret.
3. Once the tool is installed you must authenticate the tool with Strava, run:
   ``` shell
   ./strava_tool/main.py auth login
   ```
   This will direct you to navigate to a local web server in your browser. Sign in to Strava here and then end the command with Ctrl+C. 
   
   Now future CLI commands can make changes in Strava on your behalf.

# Commands
The following commands are available

## Command - Auth - Login
Login to Strava:

``` shell
... auth login --client-id ID --client-secret SECRET
```

This command will start a local web server. This server will redirect you to the Strava login page. Then it will receive the response from Strava once you login.

After you successfully login you can end this command.

This will store your API credentials in an authentication file. See the [authentication file instructions](#authentication-file) for more details.

If you've logged in at least once, and you need to re-login because your credentials expired then you can leave out the `--client-id` and `--client-secret` arguments.

## Command - Auth - Logout
Deletes the authentication file. Making it so the tool can no longer read or edit any of your Strava activities.

## Command - Update Activities
Update multiple activities at once. Define fields on which to filter and fields to update on the matched activities.

Filtering current supports the fields:

- Sport Type (`--filter-sport-type`)

The following activity fields can be updated:

- Name (`--set-name`)
- Sport Type (`--set-sport-type`)

Usage:

``` shell
... update-activites [--filter-sport-type TYPE] [--set-name NAME] [--set-sport-type TYPE]
```

# Internals
Internal implementation details.

## Authentication File
Once you log in to Strava the Strava server will send back a temporary code. This code allows limited access to your Strava account. This code is not your password, and eventually will expire.

To make the tool more convenient this code is stored in a file, along with a few other details. If someone gets ahold of this file they will be able to read and edit all of your Strava activities. So be careful.

You can change the location of this file by providing the `--auth-file FILE` argument to any command.
