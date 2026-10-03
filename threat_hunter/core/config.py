import os
from typing import Optional
from pydantic import BaseModel, Field
import yaml


class SplunkConfig(BaseModel):
    host: str = "localhost"
    port: int = 8089
    username: str = "admin"
    password_env: str = "SPLUNK_PASSWORD"
    status: str = "no api key"


class ElasticsearchConfig(BaseModel):
    host: str = "localhost"
    port: int = 9200
    username: str = "elastic"
    password_env: str = "ELASTIC_PASSWORD"
    status: str = "no api key"


class VirusTotalConfig(BaseModel):
    api_key_env: str = "VIRUSTOTAL_API_KEY"
    status: str = "no api key"


class AbuseIPDBConfig(BaseModel):
    api_key_env: str = "ABUSEIPDB_API_KEY"
    status: str = "no api key"


class SlackConfig(BaseModel):
    webhook_env: str = "SLACK_WEBHOOK"
    status: str = "no api key"


class ThreatHunterConfig(BaseModel):
    splunk: SplunkConfig = Field(default_factory=SplunkConfig)
    elasticsearch: ElasticsearchConfig = Field(default_factory=ElasticsearchConfig)
    virustotal: VirusTotalConfig = Field(default_factory=VirusTotalConfig)
    abuseipdb: AbuseIPDBConfig = Field(default_factory=AbuseIPDBConfig)
    slack: SlackConfig = Field(default_factory=SlackConfig)

    class Config:
        arbitrary_types_allowed = True


def load_config(config_file: str = "config.yaml") -> ThreatHunterConfig:
    """Load config from YAML file. Returns defaults if file not found."""
    if not os.path.exists(config_file):
        return ThreatHunterConfig()
    
    try:
        with open(config_file, 'r') as f:
            data = yaml.safe_load(f) or {}
        return ThreatHunterConfig(**data)
    except Exception as e:
        print(f"Error loading config: {e}. Using defaults.")
        return ThreatHunterConfig()


def get_secret(env_var: str) -> Optional[str]:
    """Get secret from environment variable (.env file)"""
    return os.getenv(env_var)