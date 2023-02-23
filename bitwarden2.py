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

