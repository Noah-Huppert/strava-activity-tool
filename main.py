#!/usr/bin/env python3
import logging
import argparse
import json

import stravalib
import pydantic

logging.basicConfig(level=logging.DEBUG)

DEFAULT_AUTH_FILE = "auth.json"

class AuthFile(pydantic.BaseModel):
    access_token: str
    refresh_token: str

def main():
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
    auth_subp = authp.add_subparsers(dest="subsubcmd")

    # ... url
    auth_urlp = auth_subp.add_parser("url")
    auth_urlp.add_argument(
        "--client-id",
        help="Client ID from Strava API app",
        required=True,
    )
    auth_urlp.add_argument(
        "--redirect-uri",
        help="Redirect URI, must be added to your API app",
        default="http://localhost",
    )

    # ... login
    auth_loginp = auth_subp.add_parser("login")
    auth_loginp.add_argument(
        "--client-id",
        help="Client ID from Strava API app",
        required=True,
    )
    auth_loginp.add_argument(
        "--client-secret",
        help="Client secret from Strava API app",
        required=True,
    )
    auth_loginp.add_argument(
        "--code",
        help="Code returned in URL",
        required=True,
    )

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

    if args.subcmd == "auth":
        if args.subsubcmd == "url":
            logging.info("Ensure your Strava API app has '%s' as an allowed redirect URI", args.redirect_uri)

            url = strava.authorization_url(
                client_id=args.client_id,
                redirect_uri=args.redirect_uri,
            )

            logging.info("Go to: %s", url)
        if args.subsubcmd == "login":
            resp = strava.exchange_code_for_token(
                client_id=args.client_id,
                client_secret=args.client_secret,
                code=args.code,
            )

            auth_file = AuthFile(
                access_token=resp['access_token'],
                refresh_token=resp['refresh_token'],
            )

            with open(args.auth_file, 'w') as f:
                json.dump(auth_file.dict(), f)

            logging.info("Saved authentication info in '%s'", args.auth_file)

if __name__ == '__main__':
    main()
