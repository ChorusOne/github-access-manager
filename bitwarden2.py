#!/usr/bin/env python3

from __future__ import annotations
from dataclasses import dataclass
from difflib import SequenceMatcher

import json
import os
import requests
import sys
import tomllib

from http.client import HTTPSConnection, HTTPResponse
from typing import (
    Any,
    Dict,
    List,
    Generic,
    Tuple,
    NamedTuple,
    Set,
    Iterable,
    Protocol,
    TypeVar,
)
class Member(NamedTuple):
    id: str
    name: str
    email: str
    type: int
    accessAll: bool
    # groups: Tuple[str, ...]

    def get_id(self) -> str:
        return self.id

    @staticmethod
    def from_toml_dict(data: Dict[str, Any]) -> Member:
        return Member(
            id=data["member_id"],
            name=data["member_name"],
            email = data["email"],
            type = data["type"],
            accessAll = data["accessAll"],
        )

    def format_toml(self) -> str:
        lines = [
            "[[member]]",
            f"member_id = {self.id}",
            f"member_name = {self.name}",
            f"email = {self.email}",
            f"type = {str(self.type)}",
            f"accessAll = {str(self.accessAll)}",
        ]
        return "\n".join(lines)

class GroupMember(NamedTuple):
    member_id: int
    member_name: str
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
    accessAll: bool

    def get_id(self) -> str:
        return self.id

    @staticmethod
    def from_toml_dict(data: Dict[str, Any]) -> Group:
        return Group(
            id=data["group_id"],
            name=data["group_name"],
            accessAll = data["accessAll"],
        )

    def format_toml(self) -> str:
        lines = [
            "[[group]]",
            f"group_id = {self.id}",
            f"group_name = {self.name}",
            f"accessAll = {str(self.accessAll)}",
        ]
        return "\n".join(lines)


class MemberCollectionAccess(NamedTuple):
    id: str
    name: str
    group: str

    def get_id(self) -> str:
        return self.id

    @staticmethod
    def from_toml_dict(data: Dict[str, Any]) -> MemberCollectionAccess:
        return MemberCollectionAccess(
            id=data["member_id"],
            name=data["member_name"],
            group = data["group"],
        )

    def format_toml(self) -> str:
        return (
            "{ member_id = "
            + self.id
            + ', member_name = "'
            + self.name
            + '", role = "'
            + self.group
            + '" }'
        )

class GroupCollectionAccess(NamedTuple):
    id: str
    name: str
    readOnly: bool

    def get_id(self) -> str:
        return self.id

    @staticmethod
    def from_toml_dict(data: Dict[str, Any]) -> GroupCollectionAccess:
        return GroupCollectionAccess(
            id=data["group_id"],
            name=data["group_name"],
            readOnly=data["readOnly"],
        )

    def format_toml(self) -> str:
        return (
            "{ group_id = "
            + self.id
            + ', group_name = "'
            + self.name
            + '", readOnly = "'
            + str(self.readOnly)
            + '" }'
        )

class Collection(NamedTuple):
    id: str
    externalId: str
    group_access: Tuple[GroupCollectionAccess, ...]
    member_access: Tuple[MemberCollectionAccess, ...]

    def get_id(self) -> str:
        return self.id

    @staticmethod
    def from_toml_dict(data: Dict[str, Any]) -> Collection:
        return Collection(
            id=data["collection_id"],
            externalId=data["external_id"],
            group_access=tuple(
                sorted(
                    GroupCollectionAccess.from_toml_dict(x) for x in data["group_access"]
                )
            ),
            member_access=tuple(
                sorted(
                    MemberCollectionAccess.from_toml_dict(x) for x in data["member_access"]
                )
            ),
      )

class BitwardenClient(NamedTuple):
    connection: HTTPSConnection
    bearer_token: str

    @staticmethod
    def new(client_id: str, client_secret: str) -> BitwardenClient:
        response = requests.post(
            "https://identity.bitwarden.com/connect/token",
            headers={ "Content-Type": "application/x-www-form-urlencoded" },
            data={
                "grant_type": "client_credentials",
                "scope": "api.organization",
                "Accept": "application/json",
            },
            auth=(client_id, client_secret),
        )
        bearer_token = response.json()["access_token"]
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

    def get_group(self, id: str) -> Any:
        return json.load(self._http_get(f"/public/groups/{id}"))

    def get_groups(self) -> Iterable[Group]:
        data = self._http_get(f"/public/groups")
        groups = json.load(data)
        for group in groups["data"]:
            yield Group(
                id=group["id"],
                name=group["name"],
                accessAll=group["accessAll"],
            )

    def get_collection_members(self, groups: Tuple[GroupCollectionAccess, ...]) -> Iterable[MemberCollectionAccess]:
            for group in groups:
                data = self._http_get(f"/public/groups/{group.id}/member-ids")
                memberIDs = json.load(data)

                for memberID in memberIDs:
                    data = self._http_get(f"/public/members/{memberID}")
                    member = json.load(data)
                    yield MemberCollectionAccess(
                        id=member["id"],
                        name=member["name"],
                        group=group.id,
                    )

    def get_collections(self) -> Iterable[Collection]:
        data = self._http_get(f"/public/collections")
        collections = json.load(data)

        for collection in collections["data"]:
            group_accesses = tuple(sorted(self.get_collection_groups(collection["id"])))
            member_accesses = tuple(sorted(self.get_collection_members(group_accesses)))

            yield Collection(
                id=collection["id"],
                externalId=collection["externalId"],
                member_access=member_accesses,
                group_access=group_accesses,
            )

    def get_collection_groups(self, id: str) -> Iterable[GroupCollectionAccess]:
            data = self._http_get(f"/public/collections/{id}")
            collection = json.load(data)

            for group in collection["groups"]:
                yield GroupCollectionAccess(
                    id=group["id"],
                    name=self.get_group(group["id"])["name"],
                    readOnly=group["readOnly"],
                )

    def get_group_members(self, id: str, name: str) -> Iterable[str]:
        members = json.load(self._http_get(f"/public/groups/{id}/member-ids"))

        for member in members:
            member = json.load(self._http_get(f"/public/members/{member}"))
            yield GroupMember(
                member_id=member["id"],
                member_name=member["name"],
                group_name=name,
            )

    def get_members(self) -> Iterable[Member]:
        data = self._http_get(f"/public/members")
        members= json.load(data)

        for member in members["data"]:

            yield Member(
                id=member["id"],
                name=member["name"],
                email=member["email"],
                type=member["type"],
                accessAll=member["accessAll"],
            )

class Configuration(NamedTuple):
    collection: Set[Collection]
    member: Set[Member]
    group: Set(Group)
    group_memberships: Set[GroupMember]

    @staticmethod
    def from_toml_dict(data: Dict[str, Any]) -> Configuration:
        collection = {Collection.from_toml_dict(c) for c in data["collection"]}
        member = {Member.from_toml_dict(m) for m in data["member"]}
        group = {Group.from_toml_dict(m) for m in data["group"]}
        group_memberships = {
            GroupMember(
                member_id=member["member_id"],
                member_name=member["member_name"],
                group_name=group,
            )
            for member in data["member"]
            for group in member.get("groups", [])
        }
        return Configuration(
            collection=collection,
            member=member,
            group=group,
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

def print_group_members_diff(
    *,
    group_name: str,
    target_fname: str,
    target_members: Set[GroupMember],
    actual_members: Set[GroupMember],
) -> None:
    members_diff = Diff.new(
        target=target_members,
        actual=actual_members,
    )
    if len(members_diff.to_remove) > 0:
        print(
            f"The following members of group '{group_name}' are not specified "
            f"in {target_fname}, but are present on Bitwarden:\n"
        )
        for member in sorted(members_diff.to_remove):
            print(f"  {member.member_name}")
        print()

    if len(members_diff.to_add) > 0:
        print(
            f"The following members of group '{group_name}' are specified "
            f"in {target_fname}, but are not present on Bitwarden:\n"
        )
        for member in sorted(members_diff.to_add):
            print(f"  {member.member_name}")
        print()