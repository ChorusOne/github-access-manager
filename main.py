#!/usr/bin/env python3
from __future__ import annotations

import os
import sys
import json
import tomli

from typing import (
    Any,
    Dict,
    Generic,
    Iterable,
    List,
    NamedTuple,
    Optional,
    Set,
    TypeVar,
    Protocol,
)
from enum import Enum
from http.client import HTTPSConnection, HTTPResponse
from dataclasses import dataclass


class OrganizationRole(Enum):
    ADMIN = "admin"
    MEMBER = "member"


class OrganizationMember(NamedTuple):
    user_id: int
    user_name: str
    role: OrganizationRole

    @staticmethod
    def from_toml_dict(data: Dict[str, Any]) -> OrganizationMember:
        return OrganizationMember(
            user_id=data["github_user_id"],
            user_name=data["github_user_name"],
            role=OrganizationRole(data["role"]),
        )

    def format_toml(self) -> str:
        return (
            "[[member]]\n"
            f"github_user_id = {self.user_id}\n"
            # Splicing the string is safe here, because GitHub usernames are
            # very restrictive and do not contain quotes.
            f'github_user_name = "{self.user_name}"\n'
            f'role = "{self.role.value}"'
        )


class Team(NamedTuple):
    team_id: str
    name: str
    description: str
    parent_team_name: Optional[str]

    def format_toml(self) -> str:
        lines = [
            "[[team]]",
            f"github_team_id = {self.team_id}",
            # Splicing the string is safe here, because GitHub team names are
            # very restrictive and do not contain quotes.
            f'name = "{self.name}"',
            f"description = {json.dumps(self.description)}",
        ]
        if self.parent_team_name is not None:
            lines.append(f"parent = {json.dumps(self.parent_team_name)}")

        return "\n".join(lines)


class Organization(NamedTuple):
    name: str
    members: Set[OrganizationMember]

    @staticmethod
    def from_toml_dict(data: Dict[str, Any]) -> Organization:
        members = {OrganizationMember.from_toml_dict(m) for m in data["member"]}
        return Organization(
            name=data["organization"]["name"],
            members=members,
        )

    @staticmethod
    def from_toml_file(fname: str) -> Organization:
        with open(fname, "r", encoding="utf-8") as f:
            data = tomli.load(f)
            return Organization.from_toml_dict(data)


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
            raise Exception(f"Got {response.status} from {url!r}: {body!r}", response)

    def get_organization_members(self, org: str) -> Iterable[OrganizationMember]:
        members = self._http_get_json(f"/orgs/{org}/members")
        for i, member in enumerate(members):
            username: str = member["login"]
            print(
                f"\r[{i + 1} / {len(members)}] Retrieving membership: {username}",
                end="",
                file=sys.stderr,
            )
            membership: Dict[str, Any] = self._http_get_json(
                f"/orgs/{org}/memberships/{username}"
            )
            yield OrganizationMember(
                user_name=username,
                user_id=member["id"],
                role=OrganizationRole(membership["role"]),
            )

    def get_organization_teams(self, org: str) -> Iterable[Team]:
        teams = self._http_get_json(f"/orgs/{org}/teams")
        for team in teams:
            parent_team = team["parent"]
            yield Team(
                team_id=team["id"],
                name=team["name"],
                description=team["description"],
                parent_team_name=parent_team["name"]
                if parent_team is not None
                else None,
            )


T = TypeVar("T", bound="Comparable")


class Comparable(Protocol):
    def __eq__(self: T, other: Any) -> bool:
        ...

    def __lt__(self: T, other: T) -> bool:
        ...


@dataclass(frozen=True)
class Diff(Generic[T]):
    to_add: List[T]
    to_remove: List[T]

    @staticmethod
    def new(target: Set[T], actual: Set[T]) -> Diff[T]:
        return Diff(
            to_add=sorted(target - actual),
            to_remove=sorted(actual - target),
        )


def main() -> None:
    github_token = os.getenv("GITHUB_TOKEN")
    if github_token is None:
        print("Expected GITHUB_TOKEN environment variable to be set.")
        sys.exit(1)

    if len(sys.argv) < 2:
        print("Expected file name of config toml as first argument.")
        sys.exit(1)

    target_fname = sys.argv[1]
    target_org = Organization.from_toml_file(target_fname)

    client = GithubClient.new(github_token)
    current_teams = set(client.get_organization_teams(target_org.name))

    print(
        f"The following teams in the GitHub organization are not specified in {target_fname}:"
    )
    for team in current_teams:
        print("\n" + team.format_toml())

    sys.exit(1)

    current_members = set(client.get_organization_members(target_org.name))

    diff = Diff.new(target=target_org.members, actual=current_members)
    if len(diff.to_add) > 0:
        print(
            f"The following members are specified in {target_fname} but not a member of the GitHub organization:"
        )
        for member in diff.to_add:
            print("\n" + member.format_toml())

        print()

    if len(diff.to_remove) > 0:
        print(
            f"The following members of the GitHub organization are not specified in {target_fname}:"
        )
        for member in diff.to_remove:
            print("\n" + member.format_toml())

        print()


if __name__ == "__main__":
    main()
