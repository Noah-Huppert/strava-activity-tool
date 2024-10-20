#!/usr/bin/env python3
from typing import Optional
import sys
import os
import logging
import argparse
import json

import stravalib
import pydantic
import flask
from urllib.parse import urlparse, urljoin

logging.basicConfig(level=logging.DEBUG)

DEFAULT_AUTH_FILE = "auth.json"

class AuthFile(pydantic.BaseModel):
    """Contents of file which stores authentication information.
    Fields:
        access_token: Latest authentication token, might be expired
        refresh_token: Used to retrieve new access tokens
    """
    client_id: str
    client_secret: str
    access_token: str
    refresh_token: str

class MalformedAuthFileError(Exception):
    """The auth file being read does not match the required format."""

class AuthFileService:
    """Manages the auth file.

    Fields:
        _path: Path of auth file
    """
    _path: str

    def __init__(self, path: str):
        """Initialize,"""
        self._path = path

    def save(self, data: AuthFile):
        """Save contents of auth file."""
        with open(self._path, 'w') as f:
            json.dump(data.dict(), f)

    def get(self) -> Optional[AuthFile]:
        """Read contents of auth file.
        Returns:
            Auth file if the file exists, None if it doesn't exist

        Raises:
            MalformedAuthFileError
        """
        try:
            with open(self._path, 'r') as f:
                return AuthFile.parse_obj(json.load(f))
        except FileNotFoundError:
            return None
        except pydantic.ValidationError as e:
            raise MalformedAuthFileError(str(e)) from e

    def clear(self):
        """Delete auth file."""
        try:
            os.remove(self._path)
        except FileNotFoundError:
            pass


auth_flask = flask.Flask(__name__)

@auth_flask.get("/")
def auth_flask_redirect():
    """Endpoint in authentication flask app which redirects to the Strava login website.

    Adds the correct parameters like client ID and redirect URI to the login website URL.
    """
    strava = stravalib.Client()

    with auth_flask.app_context():
        url = strava.authorization_url(
            client_id=auth_flask.config['strava_client_id'],
            redirect_uri=auth_flask.config['strava_redirect_url'],
        )

        return flask.redirect(url)

@auth_flask.get("/callback")
def auth_flask_callback():
    """Endpoint in authentication flask app which receives half completed Strava auth flow.

    Saves the result to an AuthFile.
    """
    strava = stravalib.Client()

    code = flask.request.args.get('code')
    if code is None:
        return "The query parameter 'code' is required", 400


    with auth_flask.app_context():
        auth_file_svc = AuthFileService(path=auth_flask.config['strava_auth_file'])

        resp = strava.exchange_code_for_token(
            client_id=auth_flask.config['strava_client_id'],
            client_secret=auth_flask.config['strava_client_secret'],
            code=code,
        )

        auth_file = AuthFile(
            client_id=auth_flask.config['strava_client_id'],
            client_secret=auth_flask.config['strava_client_secret'],
            access_token=resp['access_token'],
            refresh_token=resp['refresh_token'],
        )

        auth_file_svc.save(auth_file)

    return "Done! You may end this CLI command", 200

def main() -> int:
    """Entrypoint.

    Returns:
        Exit code
    """
    # Parse arguments
    parser = argparse.ArgumentParser(description="Tool to perform actions via Strava API")
    parser.add_argument(
        "--auth-file",
        help="Location of authentication file",
        default=DEFAULT_AUTH_FILE,
    )

    subp = parser.add_subparsers(dest="subcmd")

    # auth
    authp = subp.add_parser("auth")
    auth_subp = authp.add_subparsers(dest="subsubcmd", required=True)

    auth_loginp = auth_subp.add_parser("login")
    auth_loginp.add_argument(
        "--client-id",
        help="Client ID from Strava API app",
    )
    auth_loginp.add_argument(
        "--client-secret",
        help="Client secret from Strava API app",
    )

    auth_loginp.add_argument(
        "--host",
        help="Host on which login UI is hosted, must be accessed via a redirect URL added to your API app",
        default="http://localhost:8000",
    )

    auth_clearp = auth_subp.add_parser("logout")

    # convert-activities
    conv_actp = subp.add_parser("convert-activities")
    conv_actp.add_argument(
        "--from-activity",
        help="Type of activity to convert from",
        required=True,
    )
    conv_actp.add_argument(
        "--to-activity",
        help="Type of activity to convert in to",
        required=True,
    )

    args = parser.parse_args()

    # Run
    log = logging.getLogger("main")

    strava = stravalib.Client()
    auth_file_svc = AuthFileService(path=args.auth_file)

    if args.subcmd == "auth":
        if args.subsubcmd == "login":
            # Prepare server
            auth_file = auth_file_svc.get()
            client_id = args.client_id
            client_secret = args.client_secret
            if auth_file is None and (args.client_id is None or args.client_secret is None):
                logging.error("Must provide --client-id and --client-secret options")
                return 1

            if auth_file is not None:
                client_id = auth_file.client_id
                client_secret = auth_file.client_secret


            host_url = urlparse(args.host)

            auth_flask.config['SERVER_NAME'] = f"{host_url.hostname}:{host_url.port}"
            auth_flask.config['APPLICATION_ROOT'] = "/"
            auth_flask.config['PREFERRED_URL_SCHEME'] = host_url.scheme

            redirect_url = host_url._replace(
                path=urljoin(host_url.path, "/callback"),
            )

            with auth_flask.app_context():
                auth_flask.config.update({
                    'strava_client_id': client_id,
                    'strava_client_secret': client_secret,
                    'strava_redirect_url': redirect_url.geturl(),
                    'strava_auth_file': args.auth_file,
                })

            # Run server
            logging.info("Running local server, visit it to login to Strava: %s", args.host)
            with auth_flask.app_context():
                logging.info("Your Strava API app MUST HAVE %s/%s as a redirect URI, or else this won't work", args.host, flask.url_for('auth_flask_callback'))

            auth_flask.run(debug=True, host=host_url.hostname, port=host_url.port)
        elif args.subsubcmd == "logout":
            auth_file_svc.clear()
            logging.info("All local authentication data deleted")

    return 0

if __name__ == '__main__':
    sys.exit(main())
