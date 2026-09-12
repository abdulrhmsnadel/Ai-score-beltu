from __future__ import annotations

import re
from abc import ABC, abstractmethod
from dataclasses import dataclass

import httpx


@dataclass(slots=True)
class MailMessage:
    message_id: str
    sender: str
    subject: str
    text: str
    html: str | None = None


class MailboxAdapter(ABC):
    @abstractmethod
    def list_messages(self) -> list[MailMessage]:
        raise NotImplementedError

    @abstractmethod
    def get_message(self, message_id: str) -> MailMessage:
        raise NotImplementedError

    def find_verification_link(self, message: MailMessage) -> str | None:
        match = re.search(r"https?://[^\s<>\"']+", message.html or message.text)
        return match.group(0).rstrip(".,);]}") if match else None

    def find_otp(self, message: MailMessage) -> str | None:
        match = re.search(r"\b(\d{4,8})\b", message.text)
        return match.group(1) if match else None


class MailpitAdapter(MailboxAdapter):
    """Adapter for a local Mailpit instance. Designed for disposable test identities."""

    def __init__(self, base_url: str = "http://127.0.0.1:8025", timeout: float = 5) -> None:
        self.base_url = base_url.rstrip("/")
        self.timeout = timeout

    def list_messages(self) -> list[MailMessage]:
        with httpx.Client(timeout=self.timeout) as client:
            r = client.get(f"{self.base_url}/api/v1/messages")
            r.raise_for_status()
            data = r.json()
        return [MailMessage(message_id=str(item.get("ID", "")), sender=str(item.get("From", "")), subject=str(item.get("Subject", "")), text="", html=None) for item in data.get("messages", [])]

    def get_message(self, message_id: str) -> MailMessage:
        with httpx.Client(timeout=self.timeout) as client:
            r = client.get(f"{self.base_url}/api/v1/message/{message_id}")
            r.raise_for_status()
            data = r.json()
        return MailMessage(message_id=message_id, sender=str(data.get("From", "")), subject=str(data.get("Subject", "")), text=str(data.get("Text", "")), html=str(data.get("HTML", "")) or None)
