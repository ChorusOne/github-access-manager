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