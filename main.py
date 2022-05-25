#!/usr/bin/env python3
from __future__ import annotations

import os
import sys
import json

from typing import Any, Dict, NamedTuple
from enum import Enum
from http.client import HTTPSConnection, HTTPResponse


class GithubClient(NamedTuple):
    connection: HTTPSConnection
    github_token: str

    @staticmethod
    def new(github_token: str) -> GithubClient:
        timeout_seconds = 10
        connection = HTTPSConnection(
            "api.github.com",
            timeout=timeout_seconds,
        )
        return GithubClient(
            connection,
            github_token,
        )

    def _http_get(self, url: str) -> HTTPResponse:
        self.connection.request(
            method="GET",
            url=url,
            headers={
                "Authorization": f"token {self.github_token}",
                "Accept": "application/vnd.github.v3+json",
                "User-Agent": "Github Access Manager",
            },
        )
        return self.connection.getresponse()

    def _http_get_json(self, url: str) -> Dict[str, Any]:
        with self._http_get(url) as response:
            if response.status != 200:
                body = response.read()
                raise Exception(f"Got {response.status} from {url}: {body}", response)

            return json.load(response)


class OrganizationRole(Enum):
    ADMIN = "admin"
    MEMBER = "member"


class OrganizationMember(NamedTuple):
    user_id: int
    user_name: str
    role: OrganizationRole


def main() -> None:
    github_token = os.getenv("GITHUB_TOKEN")
    if github_token is None:
        print("Expected GITHUB_TOKEN environment variable to be set.")
        sys.exit(1)

    client = GithubClient.new(github_token)
    print(client._http_get_json("/orgs/ChorusOne/members"))


if __name__ == "__main__":
    main()
