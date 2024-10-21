#!/usr/bin/env python3
from typing import Optional, TypedDict
import typing
import sys
import os
import logging
import argparse
import json

import stravalib
import pydantic
import flask
from urllib.parse import urlparse, urljoin
import time

logging.basicConfig(level=logging.DEBUG)
logging.getLogger("stravalib").setLevel(logging.ERROR)
logging.getLogger("urllib3").setLevel(logging.WARN)

DEFAULT_AUTH_FILE = "auth.json"

class AuthFile(pydantic.BaseModel):
    """Contents of file which stores authentication information.
    Fields:
        client_id: Strava API client ID
        client_secret: Strava API client secret
        access_token: Latest authentication token, might be expired
        access_token_expires_at: Unix time of access token expiration
        refresh_token: Used to retrieve new access tokens
    """
    client_id: str
    client_secret: str
    access_token: str
    access_token_expires_at: int
    refresh_token: str

class AuthFileAPIResp(TypedDict):
    """Strava API response which contains new auth file data."""
    access_token: str
    refresh_token: str
    expires_at: int

class MalformedAuthFileError(Exception):
    """The auth file being read does not match the required format."""

class NeedStravaLoginError(Exception):
    """Indicates the user needs to log in to strava before anything can procede."""

    def __init__(self):
        """Initialize."""
        super().__init__("Please login with ... auth login")

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
            json.dump(data.model_dump(), f)

    def get(self) -> Optional[AuthFile]:
        """Read contents of auth file.
        Returns:
            Auth file if the file exists, None if it doesn't exist

        Raises:
            MalformedAuthFileError
        """
        try:
            with open(self._path, 'r') as f:
                return AuthFile.model_validate(json.load(f))
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

    def from_api_resp(self, resp: AuthFileAPIResp, **kwargs) -> AuthFile:
        """Create an AuthFile class instance from a Strava auth API response.

        Arguments:
            resp: Strava auth API response
            kwargs: Fields of AuthFile
        """
        return AuthFile(**{
            **kwargs,
            'access_token': resp['access_token'],
            'access_token_expires_at': resp['expires_at'],
            'refresh_token': resp['refresh_token'],
        })

    def refresh_access_token(self) -> Optional[AuthFile]:
        """Use refresh_token to request a new access token.

        Returns:
            Newest auth file if there was one.
        """
        auth_file = self.get()
        if auth_file is not None:
            strava = stravalib.Client()

            resp = strava.refresh_access_token(
                client_id=auth_file.client_id,
                client_secret=auth_file.client_secret,
                refresh_token=auth_file.refresh_token,
            )

            new_af = self.from_api_resp(resp, **auth_file.model_dump())
            self.save(new_af)
            return new_af

        return None

    def check_and_refresh_access_token(self) -> Optional[AuthFile]:
        """Refresh access token if it is expired.

        Returns:
            Newest auth file if there was one.
        """
        auth_file = self.get()
        if auth_file is not None:
            if auth_file.access_token_expires_at >= time.time():
                return self.refresh_access_token()

            return auth_file
        return None

    def try_strava_client(self) -> Optional[stravalib.Client]:
        """Creates a strava API client from the auth file.

        Returns:
            Strava API cloient if a valid auth file exists. Otherwise None.
        """
        auth_file = self.check_and_refresh_access_token()
        if auth_file is not None:
            return stravalib.Client(access_token=auth_file.access_token)

        return None

    def strava_client(self) -> stravalib.Client:
        """Always return a strava client, or exit with user error message.

        Raises:
            NeedStravaLogingError: If the user needs to log in
        """
        client = self.try_strava_client()
        if client is None:
            raise NeedStravaLoginError()

        return client


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
            scope=[
                'read',
                'activity:read',
                'activity:write',
            ]
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
        auth_file_svc = AuthFileService(
            path=auth_flask.config['strava_auth_file'],
        )

        resp = strava.exchange_code_for_token(
            client_id=auth_flask.config['strava_client_id'],
            client_secret=auth_flask.config['strava_client_secret'],
            code=code,
        )

        auth_file = auth_file_svc.from_api_resp(
            resp,
            client_id=auth_flask.config['strava_client_id'],
            client_secret=auth_flask.config['strava_client_secret'],
        )

        auth_file_svc.save(auth_file)

    return "Done! You may end this CLI command", 200

class ArgTypeStravaSportType:
    """Custom "Strava Sport Type" argument type for argparse."""

    def __call__(self, value: str) -> str:
        """Validate argument value."""
        possible_vals = stravalib.model.RelaxedSportType.__annotations__["root"]
        if value not in possible_vals:
            raise argparse.ArgumentTypeError(f"'{value}' is not a valid Strava Sport Type, must be one of: {possible_vals}")
        return value

def main(log: logging.Logger) -> int:
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
    conv_actp = subp.add_parser("update-activities")
    conv_actp.add_argument(
        "--write",
        help="Disable dry run mode",
        action='store_true',
    )
    conv_actp.add_argument(
        "--filter-sport-type",
        help="Filter activites to update by their sport type",
        type=ArgTypeStravaSportType(),
    )
    conv_actp.add_argument(
        "--set-sport-type",
        help="Set activity sport type value",
        type=ArgTypeStravaSportType(),
    )
    conv_actp.add_argument(
        "--set-name",
        help="Set activity name value",
    )

    args = parser.parse_args()

    # Run
    strava = stravalib.Client()
    auth_file_svc = AuthFileService(
        path=args.auth_file,
    )

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
            log.info("Running login server, visit it to login to Strava: %s", args.host)
            with auth_flask.app_context():
                log.info("Your Strava API app MUST HAVE %s/%s as a redirect URI, or else this won't work", args.host, flask.url_for('auth_flask_callback'))

            try:
                auth_flask.run(debug=True, host=host_url.hostname, port=host_url.port)
            except KeyboardInterrupt:
                log.info("Stopping login server")
        elif args.subsubcmd == "logout":
            auth_file_svc.clear()
            log.info("All local authentication data deleted")
    elif args.subcmd == "update-activities":
        strava = auth_file_svc.strava_client()

        # Validate there is at least one filter argument
        filter_fields = list()
        if args.filter_sport_type is not None:
            filter_fields.append({
                'key': 'sport_type',
                'get_value': lambda a: a.sport_type.root,
            })

        if len(filter_fields) == 0:
            log.error("Must provide at least one --filter-... argument")
            return 1

        # Validate at least one set argument
        set_fields = set()
        set_fields_dict = dict()
        if args.set_sport_type is not None:
            set_fields.add('sport_type')
            set_fields_dict['sport_type'] = args.set_sport_type
        if args.set_name is not None:
            set_fields.add('name')
            set_fields_dict['name'] = args.set_name

        set_field_values_str = ", ".join(list(map(lambda entry: f"{entry[0]}='{entry[1]}", set_fields_dict.items())))

        if len(set_fields) == 0:
            log.error("Must provide at least one --set-... argument")
            return 1

        if args.write is False:
            log.info("[DRY RUN] Running in dry run mode, no changes would be made")
            log.info("[DRY RUN] To disable dry run mode and actually make changes add the --write argument")

        total_matched = 0
        for activity in strava.get_activities():
            # Check is "from" type
            if args.filter_sport_type is not None and activity.sport_type.root != args.filter_sport_type:
                continue

            total_matched += 1

            # Update activity
            filter_field_values = []
            for field in filter_fields:
                key = field['key']
                get_value = field['get_value']

                filter_field_values.append(f"{key}='{get_value(activity)}'")
            filter_field_values_str = ", ".join(filter_field_values)

            if args.write is True:
                log.info("Updating activity %s (id=%d, %s) setting %s", activity.name, activity.id, filter_field_values_str, set_field_values_str)

                strava.update_activity(
                    activity_id=activity.id,
                    **set_fields_dict,
                )
            else:
                log.info("[DRY RUN] Would update activity %s (id=%d, %s) setting %s", activity.name, activity.id, filter_field_values_str, set_field_values_str)

        log.info("Found %d matching activity(ies)", total_matched)



    return 0

def error_handlers() -> int:
    """Wraps the main entrypoint with common error handlers."""
    try:
        log = logging.getLogger("main")
        return main(log=log)
    except NeedStravaLoginError as e:
        log.error("%s", e)
        return 1
    except MalformedAuthFileError as e:
        log.error("%s", e)
        log.error("Your authentication file, which stores your Strava login, is broken")
        log.error("Please use ... auth logout then ... auth login to fix the issue")
        return 1

if __name__ == '__main__':
    sys.exit(error_handlers())
