from typing import Optional
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field, model_validator


class StrictModel(BaseModel):
    model_config = ConfigDict(extra='forbid', str_strip_whitespace=True)


class Crop(StrictModel):
    x0: int = Field(ge=0, strict=True)
    y0: int = Field(ge=0, strict=True)
    x1: int = Field(gt=0, strict=True)
    y1: int = Field(gt=0, strict=True)

    @model_validator(mode='after')
    def ordered(self):
        if self.x1 <= self.x0 or self.y1 <= self.y0:
            raise ValueError('x1/y1 must be greater than x0/y0')
        return self


class S3Storage(StrictModel):
    bucket: str = Field(min_length=1, max_length=255)
    prefix: str = Field(default='', max_length=1024)
    region_name: str = ''
    s3_endpoint: str = ''
    aws_access_key_id: str = ''
    aws_secret_access_key: str = ''
    aws_session_token: str = ''
    aws_sse_kms_key_id: str = ''

    @model_validator(mode='after')
    def credentials(self):
        if bool(self.aws_access_key_id) != bool(self.aws_secret_access_key):
            raise ValueError('Access key and secret key must be supplied together')
        if self.s3_endpoint and not self.s3_endpoint.startswith(('https://', 'http://')):
            raise ValueError('S3 endpoint must be an HTTP(S) URL')
        return self


class CopyRequest(StrictModel):
    project_id: int = Field(gt=0)
    new_project_name: str = Field(min_length=1, max_length=200)
    crop: Crop
    source_storage: S3Storage
    idempotency_key: Optional[UUID] = None
