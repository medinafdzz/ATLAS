"""Inventory contracts with explicit permitted targets."""
from typing import Literal
from pydantic import BaseModel, ConfigDict, Field, model_validator, field_validator

class Check(BaseModel):
    model_config = ConfigDict(extra="forbid")
    id: str = Field(pattern=r"^[A-Za-z0-9_.-]{1,80}$")
    kind: Literal["executable", "process", "file", "symlink", "tcp"]
    name: str = Field(min_length=1, max_length=512)
    required: bool = True
    expected: str | None = None

    @field_validator("name")
    @classmethod
    def safe_name(cls, name):
        if any(c in name for c in "\x00\r\n"):
            raise ValueError("invalid check name")
        return name

    @model_validator(mode="after")
    def check_parameters(self):
        if self.kind in ("file", "symlink") and not self.name.startswith("/"):
            raise ValueError("absolute path required")
        if self.kind == "tcp":
            host, sep, port = self.name.rpartition(":")
            if not sep or not host or not port.isdigit() or not 1 <= int(port) <= 65535:
                raise ValueError("tcp check must be host:port")
        return self

class Host(BaseModel):
    model_config = ConfigDict(extra="forbid")
    id: str = Field(pattern=r"^[A-Za-z0-9_.-]{1,128}$")
    role: str = Field(default="generic", max_length=128)
    transport: Literal["local", "ssh"]
    address: str | None = None
    user: str | None = None
    port: int = Field(default=22, ge=1, le=65535)
    checks: list[Check] = Field(min_length=1, max_length=100)

    @model_validator(mode="after")
    def validate_host(self):
        import re
        if self.transport == "ssh":
            if not self.address or not self.user or not re.fullmatch(r"[A-Za-z0-9.-]{1,253}", self.address) or not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_.-]{0,63}", self.user):
                raise ValueError("invalid SSH host configuration")
        elif self.address or self.user:
            raise ValueError("local host cannot specify SSH fields")
        if len({check.id for check in self.checks}) != len(self.checks):
            raise ValueError("duplicate check ID")
        return self

class Manifest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    schema_version: Literal[1]
    environment: str = Field(pattern=r"^[A-Za-z0-9_.-]{1,128}$")
    hosts: list[Host] = Field(min_length=1, max_length=500)

    @model_validator(mode="after")
    def validate_hosts(self):
        if len({host.id for host in self.hosts}) != len(self.hosts):
            raise ValueError("duplicate host ID")
        return self
