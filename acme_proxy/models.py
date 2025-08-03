from typing import List, Optional

from pydantic import BaseModel, Field


class Identifier(BaseModel):
    type: str
    value: str


class Problem(BaseModel):
    type: str
    detail: str
    status: int
    subproblems: Optional[List["Problem"]] = None
    identifier: Optional[Identifier] = None
    algorithms: Optional[List[str]] = None  # For badSignatureAlgorithm errors


class Directory(BaseModel):
    new_nonce: str = Field(..., serialization_alias="newNonce")
    new_account: str = Field(..., serialization_alias="newAccount")
    new_order: str = Field(..., serialization_alias="newOrder")
    revoke_cert: str = Field(..., serialization_alias="revokeCert")
    key_change: str = Field(..., serialization_alias="keyChange")
    meta: dict[str, str] = Field(
        default_factory=lambda: {
            "termsOfService": "https://f0rth.space/none",
            "website": "https://f0rth.space",
        }
    )


class Account(BaseModel):
    status: str = "valid"
    contact: Optional[List[str]] = []
    terms_of_service_agreed: Optional[bool] = Field(None, alias="termsOfServiceAgreed")
    orders: str


class Order(BaseModel):
    status: str = "pending"
    expires: Optional[str] = None
    identifiers: List[Identifier]
    not_before: Optional[str] = Field(None, alias="notBefore")
    not_after: Optional[str] = Field(None, alias="notAfter")
    authorizations: List[str]
    finalize: str
    certificate: Optional[str] = None
    error: Optional[Problem] = None


class Challenge(BaseModel):
    type: str
    url: str
    status: str = "pending"
    token: str
    validated: Optional[str] = None
    error: Optional[Problem] = None


class Authorization(BaseModel):
    identifier: Identifier
    status: str = "pending"
    expires: Optional[str] = None
    challenges: List[Challenge]
    wildcard: Optional[bool] = False


# Models for request payloads
class NewOrderPayload(BaseModel):
    identifiers: List[Identifier]
    not_before: Optional[str] = Field(None, alias="notBefore")
    not_after: Optional[str] = Field(None, alias="notAfter")


class NewAccountPayload(BaseModel):
    contact: Optional[List[str]] = []
    terms_of_service_agreed: Optional[bool] = Field(None, alias="termsOfServiceAgreed")
    only_return_existing: Optional[bool] = Field(None, alias="onlyReturnExisting")


class FinalizePayload(BaseModel):
    csr: str
