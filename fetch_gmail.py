import base64
import datetime
import os
import re
from html.parser import HTMLParser
from urllib.parse import urlsplit

from google.auth.transport.requests import Request
from google.oauth2.credentials import Credentials
from google_auth_oauthlib.flow import InstalledAppFlow
from googleapiclient.discovery import build


SCOPES = ["https://www.googleapis.com/auth/gmail.readonly"]
DEFAULT_LOG_FILE = (
    r"C:\Program Files (x86)\ossec-agent\active-response\gmail_security.log"
)
TOKEN_FILE = "token.json"
CREDENTIALS_FILE = "credentials.json"
GMAIL_QUERY = "is:unread newer_than:5m"
MAX_BODY_LENGTH = 2000


class EmailHTMLToText(HTMLParser):
    """Convert email HTML to text while retaining useful hyperlink targets."""

    BLOCK_TAGS = {
        "address", "article", "aside", "blockquote", "br", "div", "footer",
        "h1", "h2", "h3", "h4", "h5", "h6", "header", "hr", "li",
        "main", "nav", "ol", "p", "pre", "section", "table", "td", "th",
        "tr", "ul",
    }
    IGNORED_TAGS = {"script", "style", "noscript", "template"}

    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.text_parts = []
        self.ignored_depth = 0
        self.link_stack = []

    def handle_starttag(self, tag, attrs):
        tag = tag.lower()

        if tag in self.IGNORED_TAGS:
            self.ignored_depth += 1
            return

        if self.ignored_depth:
            return

        if tag in self.BLOCK_TAGS:
            self.text_parts.append(" ")

        if tag == "a":
            href = dict(attrs).get("href", "").strip()
            self.link_stack.append(href)

    def handle_startendtag(self, tag, attrs):
        self.handle_starttag(tag, attrs)
        self.handle_endtag(tag)

    def handle_endtag(self, tag):
        tag = tag.lower()

        if tag in self.IGNORED_TAGS:
            if self.ignored_depth:
                self.ignored_depth -= 1
            return

        if self.ignored_depth:
            return

        if tag == "a" and self.link_stack:
            href = self.link_stack.pop()
            if is_useful_link(href):
                self.text_parts.append(f" [Link: {href}] ")

        if tag in self.BLOCK_TAGS:
            self.text_parts.append(" ")

    def handle_data(self, data):
        if not self.ignored_depth:
            self.text_parts.append(data)

    def get_text(self):
        return normalize_whitespace("".join(self.text_parts))


def is_useful_link(href):
    """Keep web/mail links and discard executable or embedded-content URLs."""
    if not href:
        return False

    try:
        scheme = urlsplit(href).scheme.lower()
    except ValueError:
        return False
    return scheme in ("", "http", "https", "mailto")


def normalize_whitespace(value):
    return re.sub(r"\s+", " ", value or "").strip()


def decode_base64url(data):
    if not data:
        return ""

    padded_data = data + "=" * (-len(data) % 4)
    try:
        decoded = base64.urlsafe_b64decode(padded_data.encode("ascii"))
    except (ValueError, UnicodeEncodeError):
        return ""

    return decoded.decode("utf-8", errors="replace")


def get_part_data(service, message_id, part):
    """Return inline MIME data or retrieve a Gmail attachment-backed MIME part."""
    body = part.get("body", {})
    data = body.get("data", "")

    if not data and body.get("attachmentId"):
        attachment = (
            service.users()
            .messages()
            .attachments()
            .get(
                userId="me",
                messageId=message_id,
                id=body["attachmentId"],
            )
            .execute()
        )
        data = attachment.get("data", "")

    return decode_base64url(data)


def collect_body_parts(service, message_id, payload):
    plain_parts = []
    html_parts = []

    def walk(part):
        mime_type = part.get("mimeType", "").lower()

        # Ignore attached files that happen to have a text MIME type.
        disposition = ""
        for header in part.get("headers", []):
            if header.get("name", "").lower() == "content-disposition":
                disposition = header.get("value", "").lower()
                break

        if "attachment" not in disposition:
            if mime_type == "text/plain":
                text = get_part_data(service, message_id, part)
                if text:
                    plain_parts.append(text)
            elif mime_type == "text/html":
                html = get_part_data(service, message_id, part)
                if html:
                    html_parts.append(html)

        for child in part.get("parts", []):
            walk(child)

    walk(payload)
    return plain_parts, html_parts


def html_to_text(raw_html):
    parser = EmailHTMLToText()
    try:
        parser.feed(raw_html)
        parser.close()
    except Exception:
        # HTMLParser is tolerant, but retain whatever was parsed if an unusual
        # malformed message still raises an error.
        pass
    return parser.get_text()


def extract_body(service, message_id, payload):
    plain_parts, html_parts = collect_body_parts(service, message_id, payload)

    # The href of an embedded link exists only in HTML, so prefer HTML whenever
    # Gmail supplies both multipart/alternative representations.
    if html_parts:
        body = " ".join(html_to_text(part) for part in html_parts)
        body = normalize_whitespace(body)
        if body:
            return body

    if plain_parts:
        body = normalize_whitespace(" ".join(plain_parts))
        if body:
            return body

    return "No Body Found"


def get_gmail_service():
    creds = None

    if os.path.exists(TOKEN_FILE):
        creds = Credentials.from_authorized_user_file(TOKEN_FILE, SCOPES)

    if not creds or not creds.valid:
        if creds and creds.expired and creds.refresh_token:
            creds.refresh(Request())
        else:
            flow = InstalledAppFlow.from_client_secrets_file(
                CREDENTIALS_FILE,
                SCOPES,
            )
            creds = flow.run_local_server(port=0)

        with open(TOKEN_FILE, "w", encoding="utf-8") as token:
            token.write(creds.to_json())

    return build("gmail", "v1", credentials=creds)


def get_header(headers, name, default="Unknown"):
    wanted_name = name.lower()
    return next(
        (
            header.get("value", default)
            for header in headers
            if header.get("name", "").lower() == wanted_name
        ),
        default,
    )


def sanitize_log_value(value):
    """Keep each Wazuh event on one parseable key-value log line."""
    value = normalize_whitespace(str(value or ""))
    return value.replace("\\", "/").replace('"', "'")


def format_local_timestamp(timestamp):
    return timestamp.strftime("%Y-%m-%d %H:%M:%S")


def prompt_for_log_file():
    """Ask where to write events, using the Wazuh path when left blank."""
    prompt = f"Log file location [{DEFAULT_LOG_FILE}]: "
    try:
        selected_path = input(prompt).strip().strip('"')
    except EOFError:
        selected_path = ""
    return os.path.expanduser(selected_path) if selected_path else DEFAULT_LOG_FILE


def fetch_emails():
    log_file_path = prompt_for_log_file()
    service = get_gmail_service()
    results = (
        service.users()
        .messages()
        .list(userId="me", q=GMAIL_QUERY)
        .execute()
    )
    messages = results.get("messages", [])

    if not messages:
        return

    with open(log_file_path, "a", encoding="utf-8") as log_file:
        for message_summary in messages:
            message_id = message_summary["id"]
            message = (
                service.users()
                .messages()
                .get(userId="me", id=message_id, format="full")
                .execute()
            )

            internal_date_ms = int(message.get("internalDate", 0))
            sent_datetime = datetime.datetime.fromtimestamp(
                internal_date_ms / 1000.0
            )
            sent_time = format_local_timestamp(sent_datetime)

            payload = message.get("payload", {})
            headers = payload.get("headers", [])
            subject = get_header(headers, "subject")
            sender = get_header(headers, "from")
            receiver = get_header(headers, "to")

            body = extract_body(service, message_id, payload)
            body = sanitize_log_value(body)
            if len(body) > MAX_BODY_LENGTH:
                body = body[: MAX_BODY_LENGTH - 3] + "..."

            fetch_time = format_local_timestamp(datetime.datetime.now())

            fields = {
                "fetch_time": fetch_time,
                "sent_time": sent_time,
                "integration": "gmail",
                "id": message_id,
                "from": sender,
                "to": receiver,
                "subject": subject,
                "body": body,
            }
            log_line = " ".join(
                f'{key}="{sanitize_log_value(value)}"'
                for key, value in fields.items()
            )
            log_file.write(log_line + "\n")


if __name__ == "__main__":
    fetch_emails()
