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

ASSUMPTIONS

A tool that is so flexible that it supports any kind of set-up, is necessarily
difficult to configure. Therefore this tool is opinionated about how teams and
repository access should be set up. It makes the following assumptions:

 * All team members have the normal "member" role in that team, nobody has the
   "maintainer" role — organization admins can modify team membership already.

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
    parent = "humans"

    [[member]]
    # Because usernames can be changed, we identify GitHub users by id.
    # One easy way to get a user's id is to look at the url of their avatar,
    # it's of the form "https://avatars.githubusercontent.com/u/«user-id»?v=4".
    github_user_id = 583231
    github_user_name = "octocat"

    # Role in the organization is either "member" or "admin".
    organization_role = "member"

    # A list of teams that this user should be a member of. In the case of
    # nested teams, it is possible to specify memberships at all levels
    # separately, although GitHub’s behavior is that members of the child team
    # are already considered members of the parent team anyway.
    teams = ["developers"]
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
from difflib import SequenceMatcher
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
            role=OrganizationRole(data["organization_role"]),
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
    slug: str
    description: str
    parent_team_name: Optional[str]

    def get_id(self) -> int:
        return self.team_id

    @staticmethod
    def from_toml_dict(data: Dict[str, Any]) -> Team:
        return Team(
            team_id=data.get("github_team_id", 0),
            name=data["name"],
            # By default if not specified, the team slug should be equal to its
            # name.
            slug=data.get("slug", data["name"]),
            description=data.get("description", ""),
            parent_team_name=data.get("parent", None),
        )

    def format_toml(self) -> str:
        lines = [
            "[[team]]",
            f"github_team_id = {self.team_id}",
            "name = " + json.dumps(self.name),
        ]

        # The slug defaults to the team name, only list it if they differ.
        if self.slug != self.name:
            lines.append("slug = " + json.dumps(self.slug))

        lines.append("description = " + json.dumps(self.description))

        if self.parent_team_name is not None:
            lines.append(f"parent = {json.dumps(self.parent_team_name)}")

        return "\n".join(lines)


class Organization(NamedTuple):
    name: str
    members: Set[OrganizationMember]
    teams: Set[Team]
    team_memberships: Set[TeamMember]

    @staticmethod
    def from_toml_dict(data: Dict[str, Any]) -> Organization:
        members = {OrganizationMember.from_toml_dict(m) for m in data["member"]}
        teams = {Team.from_toml_dict(m) for m in data["team"]}
        team_memberships = {
            TeamMember(
                user_id=user["github_user_id"],
                user_name=user["github_user_name"],
                team_name=team,
            )
            for user in data["member"]
            for team in user.get("teams", [])
        }
        return Organization(
            name=data["organization"]["name"],
            members=members,
            teams=teams,
            team_memberships=team_memberships,
        )

    @staticmethod
    def from_toml_file(fname: str) -> Organization:
        with open(fname, "r", encoding="utf-8") as f:
            data = tomli.load(f)
            return Organization.from_toml_dict(data)


class TeamMember(NamedTuple):
    user_id: int
    user_name: str
    team_name: str

    def get_id(self) -> str:
        # Our generic differ has the ability to turn add/removes into changes
        # for pairs with the same id, but this does not apply to memberships,
        # which do not themselves have an id, so the identity to group on is
        # the value itself.
        return f"{self.user_id}@{self.team_name}"

    def format_toml(self) -> str:
        # Needed to satisfy Diffable, but not used in this case.
        raise Exception(
            "Team memberships are not expressed in toml, "
            "please print the diffs in some other way."
        )


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
        # TODO: Deal with pagination.
        members = self._http_get_json(f"/orgs/{org}/members")
        for i, member in enumerate(members):
            username: str = member["login"]
            clear_line = "\x1b[2K\r"
            print(
                f"{clear_line}[{i + 1} / {len(members)}] Retrieving membership: {username}",
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

        # After the final status update, do put a newline on stderr. This means
        # that the final status update will remain visible.
        print("", file=sys.stderr)

    def get_organization_teams(self, org: str) -> Iterable[Team]:
        teams = self._http_get_json(f"/orgs/{org}/teams")
        for team in teams:
            parent_team = team["parent"]
            yield Team(
                team_id=team["id"],
                name=team["name"],
                slug=team["slug"],
                description=team["description"],
                parent_team_name=parent_team["name"]
                if parent_team is not None
                else None,
            )

    def get_team_members(self, org: str, team: Team) -> Iterable[TeamMember]:
        # TODO: This endpoint is paginated, deal with requesting multiple pages.
        members = self._http_get_json(f"/orgs/{org}/teams/{team.slug}/members")
        for member in members:
            yield TeamMember(
                user_name=member["login"],
                user_id=member["id"],
                team_name=team.name,
            )


def print_indented(lines: str) -> None:
    """Print the input indented by two spaces."""
    for line in lines.splitlines():
        print(f"  {line}")


def print_simple_diff(actual: str, target: str) -> None:
    """
    Print a line-based diff of the two strings, without abbreviating large
    chunks of identical lines like a standard unified diff would do.
    """
    lines_actual = actual.splitlines()
    lines_target = target.splitlines()
    line_diff = SequenceMatcher(None, lines_actual, lines_target)
    for tag, i1, i2, j1, j2 in line_diff.get_opcodes():
        if tag == "equal":
            for line in lines_actual[i1:i2]:
                print("  " + line)
        elif tag == "replace":
            for line in lines_actual[i1:i2]:
                print("- " + line)
            for line in lines_target[j1:j2]:
                print("+ " + line)
        elif tag == "delete":
            for line in lines_actual[i1:i2]:
                print("- " + line)
        elif tag == "insert":
            for line in lines_target[j1:j2]:
                print("+ " + line)
        else:
            raise Exception("Invalid diff operation.")


T = TypeVar("T", bound="Diffable")


class Diffable(Protocol):
    def __eq__(self: T, other: Any) -> bool:
        ...

    def __lt__(self: T, other: T) -> bool:
        ...

    def get_id(self: T) -> int | str:
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
                print()
                print_indented(entry.format_toml())

            print()

        if len(self.to_remove) > 0:
            print(header_to_remove)
            for entry in self.to_remove:
                print()
                print_indented(entry.format_toml())

            print()

        if len(self.to_change) > 0:
            print(header_to_change)
            for change in self.to_change:
                print()
                print_simple_diff(
                    actual=change.actual.format_toml(),
                    target=change.target.format_toml(),
                )

            print()


def print_team_members_diff(
    *,
    team_name: str,
    target_fname: str,
    target_members: Set[TeamMember],
    actual_members: Set[TeamMember],
) -> None:
    members_diff = Diff.new(
        target=target_members,
        actual=actual_members,
    )
    if len(members_diff.to_remove) > 0:
        print(
            f"The following members of team '{team_name}' are not specified "
            f"in {target_fname}, but are present on GitHub:\n"
        )
        for member in sorted(members_diff.to_remove):
            print(f"  {member.user_name}")
        print()

    if len(members_diff.to_add) > 0:
        print(
            f"The following members of team '{team_name}' are not members "
            f"on GitHub, but are specified in {target_fname}:\n"
        )
        for member in sorted(members_diff.to_add):
            print(f"  {member.user_name}")
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

    current_members = set(client.get_organization_members(target_org.name))
    members_diff = Diff.new(target=target_org.members, actual=current_members)
    members_diff.print_diff(
        f"The following members are specified in {target_fname} but not a member of the GitHub organization:",
        f"The following members of the GitHub organization are not specified in {target_fname}:",
        f"The following members on GitHub need to be changed to match {target_fname}:",
    )

    current_teams = set(client.get_organization_teams(target_org.name))
    teams_diff = Diff.new(target=target_org.teams, actual=current_teams)
    teams_diff.print_diff(
        f"The following teams specified in {target_fname} are not present on GitHub:",
        f"The following teams in the GitHub organization are not specified in {target_fname}:",
        f"The following teams on GitHub need to be changed to match {target_fname}:",
    )

    # For all the teams which we want to exist, and which do actually exist,
    # compare their members. When requesting the members, we pass in the actual
    # team, not the target team, because the endpoint needs the actual slug.
    target_team_names = {team.name for team in target_org.teams}
    existing_desired_teams = [
        team for team in current_teams if team.name in target_team_names
    ]
    for team in existing_desired_teams:
        print_team_members_diff(
            team_name=team.name,
            target_fname=target_fname,
            target_members={
                m for m in target_org.team_memberships if m.team_name == team.name
            },
            actual_members=set(client.get_team_members(target_org.name, team)),
        )


if __name__ == "__main__":
    main()
