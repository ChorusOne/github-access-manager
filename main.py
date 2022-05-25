#!/usr/bin/env python3
from __future__ import annotations

import os
import sys
import json

from typing import Any, Dict, Iterable, NamedTuple
from enum import Enum
from http.client import HTTPSConnection, HTTPResponse


class OrganizationRole(Enum):
    ADMIN = "admin"
    MEMBER = "member"


class OrganizationMember(NamedTuple):
    user_id: int
    user_name: str
    role: OrganizationRole


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
        # TODO: Respect these response headers
        # X-RateLimit-Limit: 5000
        # X-RateLimit-Remaining: 4994
        # X-RateLimit-Reset: 1653495296
        # X-RateLimit-Used: 6
        # X-RateLimit-Resource: core
        return self.connection.getresponse()

    def _http_get_json(self, url: str) -> Any:
        with self._http_get(url) as response:
            if 200 <= response.status < 300:
                return json.load(response)

            body = response.read()
            raise Exception(f"Got {response.status} from {url}: {body}", response)

    def get_organization_members(self, org: str) -> Iterable[OrganizationMember]:
        for member in self._http_get_json(f"/orgs/{org}/members"):
            username: str = member["login"]
            membership: Dict[str, Any] = self._http_get_json(f"/orgs/{org}/memberships/{username}")
            yield OrganizationMember(
                user_name=username,
                user_id=member["id"],
                role=OrganizationRole(membership["role"])
            )


def main() -> None:
    github_token = os.getenv("GITHUB_TOKEN")
    if github_token is None:
        print("Expected GITHUB_TOKEN environment variable to be set.")
        sys.exit(1)

    client = GithubClient.new(github_token)
    for member in client.get_organization_members("ChorusOne"):
        print(member)


if __name__ == "__main__":
    main()
