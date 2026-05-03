from pydantic import BaseModel, Field


class Identifier(BaseModel):
    type: str
    value: str


class Problem(BaseModel):
    type: str
    detail: str
    status: int
    subproblems: list["Problem"] | None = None
    identifier: Identifier | None = None
    algorithms: list[str] | None = None  # For badSignatureAlgorithm errors


class Directory(BaseModel):
    new_nonce: str = Field(..., serialization_alias="newNonce")
    new_account: str = Field(..., serialization_alias="newAccount")
    new_order: str = Field(..., serialization_alias="newOrder")
    revoke_cert: str | None = Field(None, serialization_alias="revokeCert")
    key_change: str | None = Field(None, serialization_alias="keyChange")
    meta: dict[str, str] = Field(
        default_factory=lambda: {
            "termsOfService": "https://f0rth.space/none",
            "website": "https://f0rth.space",
        }
    )


class Account(BaseModel):
    status: str = "valid"
    contact: list[str] | None = Field(default_factory=list)
    terms_of_service_agreed: bool | None = Field(None, alias="termsOfServiceAgreed")
    orders: str


class Order(BaseModel):
    status: str = "pending"
    expires: str | None = None
    identifiers: list[Identifier]
    not_before: str | None = Field(None, alias="notBefore")
    not_after: str | None = Field(None, alias="notAfter")
    authorizations: list[str]
    finalize: str
    certificate: str | None = None
    error: Problem | None = None


class Challenge(BaseModel):
    type: str
    url: str
    status: str = "pending"
    token: str
    validated: str | None = None
    error: Problem | None = None


class Authorization(BaseModel):
    identifier: Identifier
    status: str = "pending"
    expires: str | None = None
    challenges: list[Challenge]
    wildcard: bool | None = None


# Models for request payloads
class NewOrderPayload(BaseModel):
    identifiers: list[Identifier]
    not_before: str | None = Field(None, alias="notBefore")
    not_after: str | None = Field(None, alias="notAfter")


class NewAccountPayload(BaseModel):
    contact: list[str] | None = Field(default_factory=list)
    terms_of_service_agreed: bool | None = Field(None, alias="termsOfServiceAgreed")
    only_return_existing: bool | None = Field(None, alias="onlyReturnExisting")


class FinalizePayload(BaseModel):
    csr: str
