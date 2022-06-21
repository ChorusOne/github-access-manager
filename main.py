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
access token that has the following permissions:

 * "admin:org", which when checked implies both "read:org" and "write:org".
   This application does not modify the organization, but some organization-wide
   settings, such as the default repository permission, can only be read with
   the full "admin:org" permission, and not with "read:org".

 * "repo", which implies various subpermissions. This is needed to list private
   repositories within the organization.

You can generate a new token at https://github.com/settings/tokens.

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

    # Permission that organization members have on organization repositories.
    # Additional permissions can be granted per repository. Must be one of
    # "none", "read", "write", "admin".
    default_repository_permission = "read"

    [[team]]
    # Name of the team. In this example, you can mention the team with
    # '@acme-co/developers'.
    name = "developers"
    # Known after creating the team.
    team_id = 9999
    description = "All developers"

    # Optionally, if this team should be nested under a parent team,
    # the name of the parent. For top-level teams, this key can be omitted.
    parent = "humans"

    [[member]]
    # Because usernames can be changed, we identify GitHub users by id.
    # One easy way to get a user's id is to look at the url of their avatar,
    # it's of the form "https://avatars.githubusercontent.com/u/«user-id»?v=4".
    user_id = 583231
    user_name = "octocat"

    # Role in the organization is either "member" or "admin".
    organization_role = "member"

    # A list of teams that this user should be a member of. In the case of
    # nested teams, it is possible to specify memberships at all levels
    # separately, although GitHub’s behavior is that members of the child team
    # are already considered members of the parent team anyway.
    teams = ["developers"]

    [[repository]]
    repo_id = 1
    name = "oktokit"

    # One of "private" or "public".
    visibility = "public"

    # Users who have explicit access to this repository (outside of implicit
    # access through being part of a team or the organization). These can be
    # users that are not part of the organization. The permisssion level can
    # be "pull", "push", "maintain", or "admin". TODO.
    user_access = [
      { user_id = 583231, user_name = "octocat", permission = "push" },
    ]

    # Teams who have explicit access to this repository (outside of implicit
    # access through being a child team of a team with access).
    team_access = [
      { team_name = "admins", permission = "admin" },
      { team_name = "readers", permission = "pull" },
    ]

    # All organization repositories that do not have an explicit [[repository]]
    # entry in this file, are compared against the default settings. This
    # section supports the same keys as [[repository]], with the exception of
    # "repo_id" and "name".
    [repository_default]
    user_access = []
    team_access = [{ team_name = "admins", permission = "admin" }]

    # Visibility is optional for the default repository settings. When left
    # unspecified, and there is no explicit [[repository]] entry for a given
    # repository, we assume that its current visibility is the correct one.
    visibility = "private"
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
    Tuple,
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


class RepositoryPermissionGlobal(Enum):
    """
    Settings allowed by the default repository access setting in the
    organization settings.
    """
    NONE = "none"
    READ = "read"
    WRITE = "write"
    ADMIN = "admin"


class RepositoryPermissionLocal(Enum):
    """
    Settings allowed for users and teams in repository access settings.
    """
    PULL = "pull"
    PUSH = "push"
    PUSH = "maintain"
    ADMIN = "admin"


class RepositoryVisibility(Enum):
    PRIVATE = "private"
    PUBLIC = "public"


class TeamRepositoryAccess(NamedTuple):
    """
    When a team has direct access to a repository, and what the access level is.
    Subteams of a team gain access indirectly, but they are not listed here.
    """
    team_name: str
    permission: RepositoryPermissionLocal

    @staticmethod
    def from_toml_dict(data: Dict[str, Any]) -> TeamRepositoryAccess:
        return TeamRepositoryAccess(
            team_name=data["team_name"],
            permission=RepositoryPermissionLocal(data["permission"]),
        )

    def format_toml(self) -> str:
        return (
            "{ team_name = " +
            json.dumps(self.team_name) +
            ', permission = "' +
            self.permission.value +
            '" }'
        )


class UserRepositoryAccess(NamedTuple):
    """
    When a user has direct access to a repository, and what the access level is.
    Users can also gain access to a repository by being part of a team that has
    access, but those are not listed here.
    """
    user_id: int
    user_name: str
    permission: RepositoryPermissionLocal

    @staticmethod
    def from_toml_dict(data: Dict[str, Any]) -> UserRepositoryAccess:
        return UserRepositoryAccess(
            user_id=data["user_id"],
            user_name=data["user_name"],
            permission=RepositoryPermissionLocal(data["permission"]),
        )

    def format_toml(self) -> str:
        return (
            "{ user_id = " + str(self.user_id) +
            ', user_name = "' + self.user_name +
            '", permission = "' + self.permission.value + '" }'
        )


class OrganizationMember(NamedTuple):
    user_id: int
    user_name: str
    role: OrganizationRole

    def get_id(self) -> int:
        return self.user_id

    @staticmethod
    def from_toml_dict(data: Dict[str, Any]) -> OrganizationMember:
        return OrganizationMember(
            user_id=data["user_id"],
            user_name=data["user_name"],
            role=OrganizationRole(data["organization_role"]),
        )

    def format_toml(self) -> str:
        return (
            "[[member]]\n"
            f"user_id = {self.user_id}\n"
            # Splicing the string is safe here, because GitHub usernames are
            # very restrictive and do not contain quotes.
            f'user_name = "{self.user_name}"\n'
            f'organization_role = "{self.role.value}"'
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
            team_id=data.get("team_id", 0),
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
            f"team_id = {self.team_id}",
            "name = " + json.dumps(self.name),
        ]

        # The slug defaults to the team name, only list it if they differ.
        if self.slug != self.name:
            lines.append("slug = " + json.dumps(self.slug))

        lines.append("description = " + json.dumps(self.description))

        if self.parent_team_name is not None:
            lines.append("parent = " + json.dumps(self.parent_team_name))

        return "\n".join(lines)


class Organization(NamedTuple):
    """
    The properties of a GitHub organization that we are interested in managing.
    """

    name: str
    default_repository_permission: RepositoryPermissionGlobal

    @staticmethod
    def from_toml_dict(data: Dict[str, Any]) -> Organization:
        return Organization(
            name=data["name"],
            default_repository_permission=RepositoryPermissionGlobal(
                data["default_repository_permission"]
            ),
        )

    def format_toml(self) -> str:
        lines = [
            "[organization]",
            "name = " + json.dumps(self.name),
            f'default_repository_permission = "{self.default_repository_permission.value}"',
        ]
        return "\n".join(lines)


class Configuration(NamedTuple):
    organization: Organization
    members: Set[OrganizationMember]
    teams: Set[Team]
    team_memberships: Set[TeamMember]
    default_repo_settings: Repository
    repos_by_id: Dict[int, Repository]

    @staticmethod
    def from_toml_dict(data: Dict[str, Any]) -> Configuration:
        org = Organization.from_toml_dict(data["organization"])
        members = {OrganizationMember.from_toml_dict(m) for m in data["member"]}
        teams = {Team.from_toml_dict(m) for m in data["team"]}
        team_memberships = {
            TeamMember(
                user_id=user["user_id"],
                user_name=user["user_name"],
                team_name=team,
            )
            for user in data["member"]
            for team in user.get("teams", [])
        }
        default_repo_settings = Repository.from_toml_dict(data["repository_default"])
        repos = (Repository.from_toml_dict(r) for r in data["repository"])
        repos_by_id = {r.repo_id: r for r in repos}
        return Configuration(
            organization=org,
            members=members,
            teams=teams,
            team_memberships=team_memberships,
            default_repo_settings=default_repo_settings,
            repos_by_id=repos_by_id,
        )

    @staticmethod
    def from_toml_file(fname: str) -> Configuration:
        with open(fname, "r", encoding="utf-8") as f:
            data = tomli.load(f)
            return Configuration.from_toml_dict(data)

    def get_repository_target(self, actual: Repository) -> Repository:
        """
        Given an actual repository, look up what the target should be in the
        config. If there is an explicit entry, use that, otherwise apply the
        defaults.
        """
        target = self.repos_by_id.get(actual.repo_id)
        if target is None:
            return self.default_repo_settings._replace(
                repo_id=actual.repo_id,
                name=actual.name,
                # If the default repo settings have a visibility specified, we
                # should use that, but if it's not set then we just copy over
                # whatever value it currently is.
                visibility=self.default_repo_settings.visibility or actual.visibility
            )
        else:
            return target


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


class Repository(NamedTuple):
    repo_id: int
    name: str
    visibility: Optional[RepositoryVisibility]
    # These are tuples instead of lists to make them hashable.
    user_access: Tuple[UserRepositoryAccess, ...]
    team_access: Tuple[TeamRepositoryAccess, ...]

    def get_id(self) -> int:
        return self.repo_id

    @staticmethod
    def from_toml_dict(data: Dict[str, Any]) -> Repository:
        return Repository(
            # We use this for concrete repositories as well as the default,
            # so we should allow the id and name to be omitted.
            repo_id=data.get("repo_id", 0),
            name=data.get("name", ""),
            visibility=RepositoryVisibility(data["visibility"]) if "visibility" in data else None,
            user_access=tuple(sorted(
                UserRepositoryAccess.from_toml_dict(x) for x in data["user_access"]
            )),
            team_access=tuple(sorted(
                TeamRepositoryAccess.from_toml_dict(x) for x in data["team_access"]
            )),
        )

    def format_toml(self) -> str:
        user_access_lines = ["  " + a.format_toml() for a in sorted(self.user_access)]
        team_access_lines = ["  " + a.format_toml() for a in sorted(self.team_access)]
        result = (
            "[[repository]]\n"
            f"repo_id = {self.repo_id}\n"
            # Splicing the string is safe here, because GitHub repo names are
            # very restrictive and do not contain quotes.
            f'name = "{self.name}"\n'
        )

        # For the defaults, you might omit visibility, but when we start
        # printing diffs, then we diff against a concrete target, which does
        # need to have a visibility.
        assert self.visibility is not None
        result = result + f'visibility = "{self.visibility.value}"\n'

        if len(user_access_lines) > 0:
            result = result + "user_access = [\n" + ",\n".join(user_access_lines) + ",\n]\n"
        else:
            result = result + "user_access = []\n"

        if len(team_access_lines) > 0:
            result = result + "team_access = [\n" + ",\n".join(team_access_lines) + ",\n]"
        else:
            result = result + "team_access = []"

        return result


def parse_link_header(contents: str) -> Dict[str, str]:
    """
    Parse a Link header like

        Link: <https://api.example/?page=2>; rel="next", <https://api.example/?page=3>; rel="last"

    into a dict like

    {
        "next": "https://api.example/?page=2",
        "last": "https://api.example/?page=3",
    }
    """
    # This is probably not fully general for *any* Link header, but we only need
    # to parse the ones that GitHub returns to us.
    result: Dict[str, str] = {}
    for link in contents.split(","):
        if link == "":
            continue

        url, rel = link.split(";", maxsplit=1)
        url, rel = url.strip(), rel.strip()

        # Strip off the "decorations", the <> around the url, and quotes around
        # the rel="...". If they are not as expected, crash the program. With
        # arbitrary inputs that would be a bad idea, but we are only trying to
        # parse headers from GitHub's API here.
        assert url[0] == "<" and url[-1] == ">"
        assert rel[:4] == "rel="
        url = url[1:-1]
        rel = rel[4:]
        assert rel[0] == '"' and rel[-1] == '"'
        rel = rel[1:-1]
        result[rel] = url

    return result


def print_status_stderr(status: str) -> None:
    """
    On stderr, clear the current line with an ANSI escape code, jump back to
    the start of the line, and print the status, without a newline. This means
    that subsequent updates will overwrite each other (if nothing gets printed
    to stdout in the meantime).
    """
    clear_line = "\x1b[2K\r"
    print(f"{clear_line}{status}", end="", file=sys.stderr)


class GithubClient(NamedTuple):
    connection: HTTPSConnection
    github_token: str

    @staticmethod
    def new(github_token: str) -> GithubClient:
        # 10 seconds was not enough for the "/org/{org}/repos" endpoint.
        timeout_seconds = 15
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

    def _http_get_json_paginated(self, url: str) -> Iterable[Any]:
        next_url = url

        while True:
            with self._http_get(next_url) as response:
                if 200 <= response.status < 300:
                    links = parse_link_header(response.headers.get("link", ""))
                    items: List[Any] = json.load(response)
                    # Yield items separately, so the caller does not have to
                    # flatten the iterable of lists.
                    yield from items

                    # GitHub provides pagination links in the response headers.
                    # If there is more to fetch, there will be a rel="next"
                    # link to follow.
                    if "next" in links:
                        next_url = links["next"]
                        continue
                    else:
                        break

                body = response.read()
                raise Exception(
                    f"Got {response.status} from {next_url!r}: {body!r}", response
                )

    def get_organization(self, org: str) -> Organization:
        org_data: Dict[str, Any] = self._http_get_json(f"/orgs/{org}")
        default_repo_permission: str = org_data["default_repository_permission"]
        return Organization(
            name=org,
            default_repository_permission=RepositoryPermissionGlobal(default_repo_permission),
        )

    def get_organization_members(self, org: str) -> Iterable[OrganizationMember]:
        # Collect the members into a list first, so we can show an accurate
        # progress meter later.
        members = list(self._http_get_json_paginated(f"/orgs/{org}/members"))
        for i, member in enumerate(members):
            username: str = member["login"]
            print_status_stderr(
                f"[{i + 1} / {len(members)}] Retrieving membership: {username}",
            )
            membership: Dict[str, Any] = self._http_get_json(
                f"/orgs/{org}/memberships/{username}"
            )
            yield OrganizationMember(
                user_name=username,
                user_id=member["id"],
                role=OrganizationRole(membership["role"]),
            )

        # After the final status update, clear the line again, so the final
        # output is not mixed with status updates. (They go separately to stdout
        # and stderr anyway, but in a terminal you don’t want interleaved
        # output.)
        print_status_stderr("")

    def get_organization_teams(self, org: str) -> Iterable[Team]:
        teams = self._http_get_json_paginated(f"/orgs/{org}/teams")
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
        members = self._http_get_json_paginated(
            f"/orgs/{org}/teams/{team.slug}/members"
        )
        for member in members:
            yield TeamMember(
                user_name=member["login"],
                user_id=member["id"],
                team_name=team.name,
            )

    def get_repository_teams(self, org: str, repo: str) -> Iterable[TeamRepositoryAccess]:
        teams = self._http_get_json_paginated(f"/repos/{org}/{repo}/teams")
        for team in teams:
            yield TeamRepositoryAccess(
                team_name=team["name"],
                permission=RepositoryPermissionLocal(team["permission"]),
            )

    def get_organization_repositories(self, org: str) -> Iterable[Repository]:
        # Listing repositories is a slow endpoint, and paginated as well, print
        # some progress. Technically from the pagination headers we could
        # extract more precise progress, but I am not going to bother.
        print_status_stderr("[...] Listing organization repositories")
        repos = self._http_get_json_paginated(f"/orgs/{org}/repos")
        for i, repo in enumerate(repos):
            name = repo["name"]
            team_access = tuple(sorted(self.get_repository_teams(org, name)))
            print_status_stderr(f"[{i+1} / ??] Listing organization repositories")
            yield Repository(
                repo_id=repo["id"],
                name=name,
                visibility=RepositoryVisibility(repo["visibility"]),
                user_access=(),
                team_access=team_access,
            )
        print_status_stderr("")


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
            f"The following members of team '{team_name}' are specified "
            f"in {target_fname}, but are not present on GitHub:\n"
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
    target = Configuration.from_toml_file(target_fname)
    org_name = target.organization.name

    client = GithubClient.new(github_token)

    actual_repos = set(client.get_organization_repositories(org_name))
    target_repos = set(target.repos_by_id.values()) | {
        target.get_repository_target(r) for r in actual_repos
    }
    repos_diff = Diff.new(target=target_repos, actual=actual_repos)
    repos_diff.print_diff(
        f"The following repositories are specified in {target_fname} but not present on GitHub:",
        # Because we generate the targets from the actuals, that means there
        # should not be any repos that are present on GitHub but for which we
        # have no target.
        "You should not see this message, please report a bug.",
        f"The following repositories on GitHub need to be changed to match {target_fname}:",
    )

    sys.exit(1)

    current_org = client.get_organization(org_name)
    if current_org != target.organization:
        print("The organization-level settings need to be changed as follows:\n")
        print_simple_diff(
            actual=current_org.format_toml(),
            target=target.organization.format_toml(),
        )

    current_members = set(client.get_organization_members(org_name))
    members_diff = Diff.new(target=target.members, actual=current_members)
    members_diff.print_diff(
        f"The following members are specified in {target_fname} but not a member of the GitHub organization:",
        f"The following members are not specified in {target_fname} but are a member of the GitHub organization:",
        f"The following members on GitHub need to be changed to match {target_fname}:",
    )

    current_teams = set(client.get_organization_teams(org_name))
    teams_diff = Diff.new(target=target.teams, actual=current_teams)
    teams_diff.print_diff(
        f"The following teams specified in {target_fname} are not present on GitHub:",
        f"The following teams are not specified in {target_fname} but are present on GitHub:",
        f"The following teams on GitHub need to be changed to match {target_fname}:",
    )

    # For all the teams which we want to exist, and which do actually exist,
    # compare their members. When requesting the members, we pass in the actual
    # team, not the target team, because the endpoint needs the actual slug.
    target_team_names = {team.name for team in target.teams}
    existing_desired_teams = [
        team for team in current_teams if team.name in target_team_names
    ]
    for team in existing_desired_teams:
        print_team_members_diff(
            team_name=team.name,
            target_fname=target_fname,
            target_members={
                m for m in target.team_memberships if m.team_name == team.name
            },
            actual_members=set(client.get_team_members(org_name, team)),
        )


if __name__ == "__main__":
    main()
