#!/usr/bin/env python3

# Copyright 2022 Chorus One

# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# A copy of the License has been included in the root of the repository.

"""
Bitwarden Access Manager

Compare the current state of a Bitwarden organization with a desired state
expressed in a TOML file. Currently this tool only points out the differences,
it does not automatically reconcile them for you.

USAGE

    ./bitwarden_access_manager.py organization.toml

ENVIRONMENT

Requires BITWARDEN_CLIENT_ID and BITWARDEN_CLIENT_SECRET to be set in the environment.
Those must contain OAuth2 client credentials for the organization. Only Bitwarden
members of the organization with OWNER role have access to those credentials.

You can view the credentials at https://vault.bitwarden.com/#/organizations/<organization_id>/settings/account

CONFIGURATION

* The access_all key for members and groups is optional, default is false.
* The member_access key for a collection only list members with direct access
to collection. It omits direct access for members with the role
owners or admins because they have implicit access to all collections.

[[member]]
member_id = "2564c11f-fc1b-4ec7-aa0b-afaf00a9e4a4"
member_name = "yan"
email = "yan.68@hotmail.fr"
type = "member"
groups = ["group1"]

[[member]]
member_id = "856cba2d-cae1-40e7-96cc-afaf00a8a4cb"
member_name = "yunkel"
email = "yunkel68@hotmail.fr"
type = "owner"
access_all = true
groups = ["group1", "group2"]

[[group]]
group_id = "c6a13b93-edc1-4c3b-9fc5-afaf00a8d33f"
group_name = "group1"
access_all = true

[[group]]
group_id = "39b48ab2-81fd-40eb-87e9-afb0000110f3"
group_name = "group2"

[[collection]]
collection_id = "50351c20-55b4-4ee8-bbe0-afaf00a8f25d"
external_id = "collection1"
member_access = [
  { email = "yan@chorus.one", access = "write"},
]

group_access = [
  { group_name = "group1", access = "readonly"},
  { group_name = "group2", access = "write" },
]

[[collection]]
collection_id = "8e69ce49-85ae-4e09-a52c-afaf00a90a3f"
external_id = ""
member_access = [
  { email = "yan@chorus.one", access = "write" },
]
group_access = [
  { group_name = "group1", access = "readonly" },
]
"""

from __future__ import annotations
from collections import defaultdict
from dataclasses import dataclass
from difflib import SequenceMatcher
from enum import Enum
from http.client import HTTPSConnection, HTTPResponse
from urllib.parse import urlencode

import json
import os
import sys
import tomllib

from typing import (
    Any,
    Dict,
    Generic,
    Iterable,
    List,
    NamedTuple,
    Optional,
    Protocol,
    Set,
    Tuple,
    TypeVar,
)


class MemberType(Enum):
    OWNER = 0
    ADMIN = 1
    USER = 2
    MANAGER = 3
    CUSTOM = 4


class GroupAccess(Enum):
    READONLY = 0
    WRITE = 1


class Member(NamedTuple):
    id: str
    name: Optional[str]
    email: str
    type: MemberType
    access_all: bool
    groups: Tuple[str, ...]

    def get_id(self) -> str:
        return self.id

    @staticmethod
    def from_toml_dict(data: Dict[str, Any]) -> Member:
        access_all: bool = False
        groups: Tuple[str, ...] = tuple()

        if "access_all" in data:
            access_all = data["access_all"]

        if "groups" in data:
            groups = data["groups"]
            groups = tuple(sorted(data["groups"]))

        return Member(
            id=data["member_id"],
            name=data.get("member_name"),
            email=data["email"],
            type=MemberType[data["type"].upper()],
            access_all=access_all,
            groups=groups,
        )

    def format_toml(self) -> str:
        lines = [
            "[[member]]\n",
            f'member_id = "{self.id}"\n',
        ]

        if self.name is not None:
            lines.append(f'member_name = "{self.name}"\n')

        lines += [
            f'email = "{self.email}"\n',
            f'type = "{self.type.name.lower()}"\n',
        ]

        if self.access_all:
            lines.append("access_all = true\n")

        lines.append("groups = [" + ", ".join(json.dumps(g) for g in sorted(self.groups)) + "]\n")

        return "".join(lines)


class GroupMember(NamedTuple):
    member_id: str
    group_name: str

    def get_id(self) -> str:
        # Our generic differ has the ability to turn add/removes into changes
        # for pairs with the same id, but this does not apply to memberships,
        # which do not themselves have an id, so the identity to group on is
        # the value itself.
        return f"{self.member_id}@{self.group_name}"

    def format_toml(self) -> str:
        # Needed to satisfy Diffable, but not used in this case.
        raise Exception(
            "Group memberships are not expressed in toml, "
            "please print the diffs in some other way."
        )


class Group(NamedTuple):
    id: str
    name: str
    access_all: bool

    def get_id(self) -> str:
        return self.id

    @staticmethod
    def from_toml_dict(data: Dict[str, Any]) -> Group:
        access_all: bool = False
        if "access_all" in data:
            access_all = data["access_all"]

        return Group(
            id=data["group_id"],
            name=data["group_name"],
            access_all=access_all,
        )

    def format_toml(self) -> str:
        lines = [
            "[[group]]",
            f'group_id = "{self.id}"',
            f'group_name = "{self.name}"',
            f'access_all = {str(self.access_all).lower()}',
        ]
        return "\n".join(lines)


class MemberCollectionAccess(NamedTuple):
    # We identify members by email, name is not guaranteed to be present.
    email: str
    access: GroupAccess

    @staticmethod
    def from_toml_dict(data: Dict[str, Any]) -> MemberCollectionAccess:
        return MemberCollectionAccess(
            email=data["email"],
            access=GroupAccess[data["access"].upper()],
        )

    def format_toml(self) -> str:
        return (
            f'{{ email = {json.dumps(self.email)}, '
            f'access = "{self.access.name.lower()}" }}'
        )


class GroupCollectionAccess(NamedTuple):
    group_name: str
    access: GroupAccess

    @staticmethod
    def from_toml_dict(data: Dict[str, Any]) -> GroupCollectionAccess:
        return GroupCollectionAccess(
            group_name=data["group_name"],
            access=GroupAccess[data["access"].upper()],
        )

    def format_toml(self) -> str:
        return (
            '{ group_name = "'
            + self.group_name
            + '", access = "'
            + self.access.name.lower()
            + '" }'
        )


class Collection(NamedTuple):
    id: str
    external_id: str
    group_access: Tuple[GroupCollectionAccess, ...]
    member_access: Tuple[MemberCollectionAccess, ...]

    def get_id(self) -> str:
        return self.id

    @staticmethod
    def from_toml_dict(data: Dict[str, Any]) -> Collection:
        group_access: Tuple[GroupCollectionAccess, ...] = tuple()
        if "group_access" in data:
            group_access = tuple(
                sorted(
                    GroupCollectionAccess.from_toml_dict(x)
                    for x in data["group_access"]
                )
            )

        member_access: Tuple[MemberCollectionAccess, ...] = tuple()
        if "member_access" in data:
            member_access = tuple(
                sorted(
                    MemberCollectionAccess.from_toml_dict(x)
                    for x in data["member_access"]
                )
            )

        return Collection(
            id=data["collection_id"],
            external_id=data["external_id"],
            group_access=group_access,
            member_access=member_access,
        )

    def format_toml(self) -> str:
        lines = [
            "[[collection]]\n",
            f'collection_id = "{self.id}"\n',
            f'external_id = "{self.external_id}"\n',
        ]

        member_access_lines = [
            "  " + a.format_toml() for a in sorted(self.member_access)
        ]
        if len(member_access_lines) > 0:
            lines.extend([
                "member_access = [\n",
                ",\n".join(member_access_lines),
                ",\n]\n",
            ])
        else:
            lines.append("member_access = []\n")

        group_access_lines = [
            "  " + a.format_toml() for a in sorted(self.group_access)
        ]
        if len(group_access_lines) > 0:
            lines.extend([
                "group_access = [\n",
                ",\n".join(group_access_lines),
                ",\n]",
            ])
        else:
            lines.append("group_access = []")

        return "".join(lines)


def print_status_stderr(status: str) -> None:
    """
    On stderr, clear the current line with an ANSI escape code, jump back to
    the start of the line, and print the status, without a newline. This means
    that subsequent updates will overwrite each other (if nothing gets printed
    to stdout in the meantime).
    """
    clear_line = "\x1b[2K\r"
    print(f"{clear_line}{status}", end="", file=sys.stderr)


class BitwardenClient(NamedTuple):
    connection: HTTPSConnection
    bearer_token: str

    @staticmethod
    def new(client_id: str, client_secret: str) -> BitwardenClient:
        connection = HTTPSConnection("identity.bitwarden.com")
        connection.request(
            method="POST",
            url="/connect/token",
            headers={
                "Content-Type": "application/x-www-form-urlencoded",
            },
            body=urlencode({
                "grant_type": "client_credentials",
                "scope": "api.organization",
                "client_id": client_id,
                "client_secret": client_secret,
            }),
        )
        auth_response: Dict[str, Any] = json.load(connection.getresponse())
        bearer_token = auth_response["access_token"]
        return BitwardenClient(HTTPSConnection("api.bitwarden.com"), bearer_token)

    def _http_get(self, url: str) -> HTTPResponse:
        self.connection.request(
            method="GET",
            url=url,
            headers={
                "Accept": "application/json",
                "Authorization": f"Bearer {self.bearer_token}",
            },
        )

        return self.connection.getresponse()

    def get_groups(self) -> Iterable[Group]:
        groups = json.load(self._http_get(f"/public/groups"))
        for group in groups["data"]:
            yield Group(
                id=group["id"],
                name=group["name"],
                access_all=group["accessAll"],
            )

    def get_collections(
        self,
        org_members: Dict[str, Member],
        collections_members: Dict[str, List[MemberCollectionAccess]],
    ) -> Iterable[Collection]:
        collections = json.load(self._http_get(f"/public/collections"))

        for collection in collections["data"]:
            group_accesses: Tuple[GroupCollectionAccess, ...] = tuple()
            member_accesses: Tuple[MemberCollectionAccess, ...] = tuple()
            collection_id = collection["id"]

            collection_data = json.load(
                self._http_get(f"/public/collections/{collection_id}")
            )

            group_collection_accesses: List[GroupCollectionAccess] = []

            for group in collection_data["groups"]:
                access = self.map_access(readonly=group["readOnly"])
                group_id = group["id"]
                group_collection_accesses.append(
                    GroupCollectionAccess(
                        group_name=json.load(
                            self._http_get(f"/public/groups/{group_id}")
                        )["name"],
                        access=access,
                    )
                )

            group_accesses = tuple(sorted(group_collection_accesses))

            member_accesses = tuple(sorted(
                collections_members.get(collection_id, []),
                key=lambda ma: ma.email,
            ))

            yield Collection(
                id=collection["id"],
                external_id=collection["externalId"],
                member_access=member_accesses,
                group_access=group_accesses,
            )

    def get_group_members(
        self, group_id: str, group_name: str
    ) -> Iterable[GroupMember]:
        members = json.load(self._http_get(f"/public/groups/{group_id}/member-ids"))

        for member in members:
            member = json.load(self._http_get(f"/public/members/{member}"))
            yield GroupMember(
                member_id=member["id"],
                group_name=group_name,
            )

    def set_member_type(self, type_id: int) -> MemberType:
        int_to_member_type: Dict[int, MemberType] = {
            variant.value: variant for variant in MemberType
        }

        return MemberType(int_to_member_type[type_id])

    def get_members(
        self, member_groups: Dict[str, List[str]]
    ) -> Tuple[List[Member], Dict[str, List[MemberCollectionAccess]]]:
        data = self._http_get(f"/public/members")
        members = json.load(data)

        members_result: List[Member] = []
        collection_access: Dict[str, List[MemberCollectionAccess]] = defaultdict(
            lambda: []
        )
        groups: Tuple[str, ...] = tuple()

        for i, member in enumerate(members["data"]):
            print_status_stderr(f"[{i+1}/{len(members['data'])}] Getting member {member['email']} ...")
            type = self.set_member_type(member["type"])
            groups = tuple(sorted(member_groups[member["id"]]))
            m = Member(
                id=member["id"],
                name=member["name"],
                email=member["email"],
                type=type,
                access_all=member["accessAll"],
                groups=groups,
            )
            members_result.append(m)

            collections = json.load(self._http_get(f"/public/members/{member['id']}"))[
                "collections"
            ]
            if type != MemberType.OWNER and type != MemberType.ADMIN:
                for collection in collections:
                    access = self.map_access(readonly=collection["readOnly"])
                    collection_access[collection["id"]].append(
                        MemberCollectionAccess(
                            email=member["email"],
                            access=access,
                        )
                    )

        # Clear the member fetching status updates.
        print_status_stderr("")

        return members_result, collection_access

    def map_access(self, *, readonly: bool) -> GroupAccess:
        if readonly == True:
            return GroupAccess["READONLY"]
        else:
            return GroupAccess["WRITE"]


class Configuration(NamedTuple):
    collection: Set[Collection]
    members: Set[Member]
    groups: Set[Group]
    group_memberships: Set[GroupMember]

    @staticmethod
    def from_toml_dict(data: Dict[str, Any]) -> Configuration:
        collection = {Collection.from_toml_dict(c) for c in data["collection"]}
        members = {Member.from_toml_dict(m) for m in data["member"]}
        groups = {Group.from_toml_dict(m) for m in data["group"]}
        group_memberships = {
            GroupMember(
                member_id=member["member_id"],
                group_name=group,
            )
            for member in data["member"]
            for group in member.get("groups", [])
        }
        return Configuration(
            collection=collection,
            members=members,
            groups=groups,
            group_memberships=group_memberships,
        )

    @staticmethod
    def from_toml_file(fname: str) -> Configuration:
        with open(fname, "rb") as f:
            data = tomllib.load(f)
            return Configuration.from_toml_dict(data)


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
        # description of a group, that would show up as deleting one group and
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


def main() -> None:
    if "--help" in sys.argv:
        print(__doc__)
        sys.exit(0)

    client_id = os.getenv("BITWARDEN_CLIENT_ID")
    if client_id is None:
        print("Expected BITWARDEN_CLIENT_ID environment variable to be set.")
        print("See also --help.")
        sys.exit(1)

    client_secret = os.getenv("BITWARDEN_CLIENT_SECRET")
    if client_secret is None:
        print("Expected BITWARDEN_CLIENT_SECRET environment variable to be set.")
        print("See also --help.")
        sys.exit(1)

    if len(sys.argv) < 2:
        print("Expected file name of config toml as first argument.")
        print("See also --help.")
        sys.exit(1)

    target_fname = sys.argv[1]
    target = Configuration.from_toml_file(target_fname)
    client = BitwardenClient.new(client_id, client_secret)

    current_groups = set(client.get_groups())
    groups_diff = Diff.new(target=target.groups, actual=current_groups)
    groups_diff.print_diff(
        f"The following groups specified in {target_fname} are not present on Bitwarden:",
        f"The following groups are not specified in {target_fname} but are present on Bitwarden:",
        f"The following groups on Bitwarden need to be changed to match {target_fname}:",
    )

    # For all the groups which we want to exist, and which do actually exist,
    # compare their members.
    target_groups_names = {group.name for group in target.groups}
    existing_desired_groups = [
        group for group in current_groups if group.name in target_groups_names
    ]

    member_groups: Dict[str, List[str]] = defaultdict(lambda: [])

    for i, group in enumerate(existing_desired_groups):
        print_status_stderr(f"[{i+1}/{len(existing_desired_groups)}] Getting group {group.name} ...")
        group_members = set(client.get_group_members(group.id, group.name))

        # Create a Dict mapping member ids to the groups they are a member of.
        for group_member in group_members:
            member_groups[group_member.member_id].append(group.name)

    print_status_stderr("")

    current_members, members_access = client.get_members(member_groups)
    current_members_set = set(current_members)
    members_diff = Diff.new(target=target.members, actual=current_members_set)
    members_diff.print_diff(
        f"The following members are specified in {target_fname} but not a member of the Bitwarden organization:",
        f"The following members are not specified in {target_fname} but are a member of the Bitwarden organization:",
        f"The following members on Bitwarden need to be changed to match {target_fname}:",
    )

    org_members: Dict[str, Member] = {member.id: member for member in current_members}
    current_collections = set(client.get_collections(org_members, members_access))
    collections_diff = Diff.new(target=target.collection, actual=current_collections)
    collections_diff.print_diff(
        f"The following collections are specified in {target_fname} but not a member of the Bitwarden organization:",
        f"The following collections are not specified in {target_fname} but are a member of the Bitwarden organization:",
        f"The following collections on Bitwarden need to be changed to match {target_fname}:",
    )


if __name__ == "__main__":
    main()
