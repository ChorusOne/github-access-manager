#!/usr/bin/env python3

"""
Github Access Manager

Comare the current state of a GitHub organization against a declarative
specification of the target state. Currently this tool only points out the
differences, it does not automatically reconcile them for you.

USAGE

    ./main.py org.toml

ENVIRONMENT

Requires GITHUB_TOKEN to be set in the environment. This must contain a personal
access token that has "read:org" permission (listed under "admin:org", but the
parent permission is not needed). You can generate a new token at
https://github.com/settings/tokens.

CONFIGURATION

The input file is a toml file that describes the target state of the GitHub
organization. The format is as follows.

    [organization]
    # GitHub organization to target.
    name = "acme-co"

    # TODO: Document.
    repository_base_permission = "read"
    repository_write_access_team = "tech"

    [[team]]
    # Name of the team. In this example, you can mention the team with
    # '@acme-co/developers'.
    name = "developers"
    # Known after creating the team.
    github_team_id = 9999
    description = "All developers"

    # Optionally, if this team should be nested under a parent team,
    # the name of the parent. For top-level teams, this key can be omitted.
    parent = "tech"

    [[member]]
    # Because usernames can be changed, we identify GitHub users by id.
    # One easy way to get a user's id is to look at the url of their avatar,
    # it's of the form "https://avatars.githubusercontent.com/u/«user-id»?v=4".
    github_user_id = 583231
    github_user_name = "octocat"

    # Role in the organization is either "member" or "admin".
    role = "member"
"""

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

    def get_id(self) -> int:
        return self.user_id

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
    team_id: int
    name: str
    description: str
    parent_team_name: Optional[str]

    def get_id(self) -> int:
        return self.team_id

    @staticmethod
    def from_toml_dict(data: Dict[str, Any]) -> Team:
        return Team(
            team_id=data.get("github_team_id", 0),
            name=data["name"],
            description=data.get("description", ""),
            parent_team_name=data.get("parent", None),
        )

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
    teams: Set[Team]

    @staticmethod
    def from_toml_dict(data: Dict[str, Any]) -> Organization:
        members = {OrganizationMember.from_toml_dict(m) for m in data["member"]}
        teams = {Team.from_toml_dict(m) for m in data["team"]}
        return Organization(
            name=data["organization"]["name"],
            members=members,
            teams=teams,
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


T = TypeVar("T", bound="Diffable")


class Diffable(Protocol):
    def __eq__(self: T, other: Any) -> bool:
        ...

    def __lt__(self: T, other: T) -> bool:
        ...

    def get_id(self: T) -> int:
        ...

    def format_toml(self: T) -> str:
        ...


@dataclass(frozen=True)
class DiffEntry(Generic[T]):
    actual: T
    target: T


@dataclass(frozen=True)
class Diff(Generic[T]):
    to_add: List[T]
    to_remove: List[T]
    to_change: List[DiffEntry[T]]

    @staticmethod
    def new(target: Set[T], actual: Set[T]) -> Diff[T]:
        # A very basic diff is to just look at everything that needs to be added
        # and removed, without deeper inspection.
        to_add = sorted(target - actual)
        to_remove = sorted(actual - target)

        # However, that produces a very rough diff. If we change e.g. the
        # description of a team, that would show up as deleting one team and
        # adding back another which is almost the same, except with a different
        # description. So to improve on this a bit, if entries have ids, and
        # the same id needs to be both added and removed, then instead we record
        # that as a "change".
        to_add_by_id = {x.get_id(): x for x in to_add}
        to_remove_by_id = {x.get_id(): x for x in to_remove}
        to_change = [
            DiffEntry(
                actual=to_remove_by_id[id_],
                target=to_add_by_id[id_],
            )
            for id_ in sorted(to_add_by_id.keys() & to_remove_by_id.keys())
        ]

        # Now that we turned some add/remove pairs into a "change", we should no
        # longer count those as added/removed.
        for change in to_change:
            to_add.remove(change.target)
            to_remove.remove(change.actual)

        return Diff(
            to_add=to_add,
            to_remove=to_remove,
            to_change=to_change,
        )

    def print_diff(
        self,
        header_to_add: str,
        header_to_remove: str,
        header_to_change: str,
    ) -> None:
        if len(self.to_add) > 0:
            print(header_to_add)
            for entry in self.to_add:
                print("\n" + entry.format_toml())

            print()

        if len(self.to_remove) > 0:
            print(header_to_remove)
            for entry in self.to_remove:
                print("\n" + entry.format_toml())

            print()

        if len(self.to_change) > 0:
            print(header_to_change)
            for change in self.to_change:
                # TODO: Print a line-based diff.
                print("\n" + "---\n" + change.actual.format_toml())
                print("\n" + "+++\n" + change.target.format_toml())

            print()


def main() -> None:
    if "--help" in sys.argv:
        print(__doc__)
        sys.exit(0)

    github_token = os.getenv("GITHUB_TOKEN")
    if github_token is None:
        print("Expected GITHUB_TOKEN environment variable to be set.")
        print("See also --help.")
        sys.exit(1)

    if len(sys.argv) < 2:
        print("Expected file name of config toml as first argument.")
        print("See also --help.")
        sys.exit(1)

    target_fname = sys.argv[1]
    target_org = Organization.from_toml_file(target_fname)

    client = GithubClient.new(github_token)
    current_teams = set(client.get_organization_teams(target_org.name))

    teams_diff = Diff.new(
        target=target_org.teams,
        actual=current_teams,
    )
    teams_diff.print_diff(
        f"The following teams specified in {target_fname} are not present on GitHub:",
        f"The following teams in the GitHub organization are not specified in {target_fname}:",
        f"The following teams on GitHub need to be changed to match {target_fname}:",
    )

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
