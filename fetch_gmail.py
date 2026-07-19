import base64
import datetime
import ipaddress
import json
import os
import re
from html.parser import HTMLParser
from pathlib import Path
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
CONFIG_FILE = Path(__file__).resolve().with_name("config.json")
GMAIL_QUERY = "is:unread newer_than:5m"
MAX_BODY_LENGTH = 2000
WEB_URL_PATTERN = re.compile(r"https?://[^\s<>\"']+", re.IGNORECASE)


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
        self.urls = []

    def handle_starttag(self, tag, attrs):
        tag = tag.lower()

        if tag in self.IGNORED_TAGS:
            self.ignored_depth += 1
            return

        if self.ignored_depth:
            return

        if tag in self.BLOCK_TAGS:
            self.text_parts.append(" ")

        attributes = dict(attrs)
        for attribute_name in ("href", "src", "action"):
            candidate = attributes.get(attribute_name, "").strip()
            normalized_url = normalize_web_url(candidate)
            if normalized_url:
                self.urls.append(normalized_url)

        if tag == "a":
            href = attributes.get("href", "").strip()
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


def normalize_web_url(value):
    """Return a usable HTTP(S) URL, excluding relative and unsafe schemes."""
    value = (value or "").strip().rstrip(".,;:!?)]}")
    try:
        parsed = urlsplit(value)
        if parsed.scheme.lower() not in ("http", "https") or not parsed.hostname:
            return ""
    except ValueError:
        return ""
    return value


def extract_web_urls(value):
    return [
        normalized
        for match in WEB_URL_PATTERN.findall(value or "")
        if (normalized := normalize_web_url(match))
    ]


def distinct(values):
    """Return non-empty values in their original order without duplicates."""
    return list(dict.fromkeys(value for value in values if value))


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

        if "attachment" not in disposition and not part.get("filename"):
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


def parse_html(raw_html):
    parser = EmailHTMLToText()
    try:
        parser.feed(raw_html)
        parser.close()
    except Exception:
        # HTMLParser is tolerant, but retain whatever was parsed if an unusual
        # malformed message still raises an error.
        pass
    text = parser.get_text()
    return text, distinct(parser.urls + extract_web_urls(text))


def html_to_text(raw_html):
    return parse_html(raw_html)[0]


def extract_content(service, message_id, payload):
    plain_parts, html_parts = collect_body_parts(service, message_id, payload)
    urls = []
    html_text_parts = []

    for raw_html in html_parts:
        text, part_urls = parse_html(raw_html)
        html_text_parts.append(text)
        urls.extend(part_urls)

    for plain_text in plain_parts:
        urls.extend(extract_web_urls(plain_text))

    # The href of an embedded link exists only in HTML, so prefer HTML whenever
    # Gmail supplies both multipart/alternative representations.
    if html_text_parts:
        body = " ".join(html_text_parts)
        body = normalize_whitespace(body)
        if body:
            return body, distinct(urls)

    if plain_parts:
        body = normalize_whitespace(" ".join(plain_parts))
        if body:
            return body, distinct(urls)

    return "No Body Found", distinct(urls)


def extract_body(service, message_id, payload):
    """Retain the original body-only interface for existing callers."""
    return extract_content(service, message_id, payload)[0]


def extract_attachment_metadata(payload):
    """Collect attachment metadata without downloading attachment contents."""
    attachments = []

    def walk(part):
        filename = normalize_whitespace(part.get("filename", ""))
        disposition = get_header(
            part.get("headers", []),
            "content-disposition",
            "",
        ).lower()

        if filename or "attachment" in disposition:
            body = part.get("body", {})
            try:
                size = int(body.get("size", 0))
            except (TypeError, ValueError):
                size = 0
            attachments.append(
                {
                    "filename": filename or "unnamed",
                    "mime_type": part.get("mimeType") or "application/octet-stream",
                    "size": size,
                }
            )

        for child in part.get("parts", []):
            walk(child)

    walk(payload)
    return attachments


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
    for header in headers:
        if header.get("name", "").lower() == wanted_name:
            return header.get("value") or default
    return default


def get_headers(headers, name):
    """Return every value for a potentially repeated message header."""
    wanted_name = name.lower()
    return [
        header.get("value", "")
        for header in headers
        if header.get("name", "").lower() == wanted_name
    ]


def select_authentication_headers(headers):
    """Prefer authentication results added at Gmail's receiving boundary."""
    primary_values = get_headers(headers, "authentication-results")
    trusted_primary = [
        value
        for value in primary_values
        if re.match(r"\s*mx\.google\.com\s*;", value, re.IGNORECASE)
    ]

    arc_values = get_headers(headers, "arc-authentication-results")
    trusted_arc = [
        value
        for value in arc_values
        if re.match(
            r"\s*i\s*=\s*\d+\s*;\s*mx\.google\.com\s*;",
            value,
            re.IGNORECASE,
        )
    ]

    # Do not treat arbitrary sender-supplied Authentication-Results as trusted
    # evidence when Gmail's authentication service is not identified.
    return trusted_primary, trusted_arc


def get_trusted_received_spf(headers):
    """Return the receiver-generated SPF header used by Gmail."""
    return [
        value
        for value in get_headers(headers, "received-spf")
        if re.match(
            r"\s*[a-z0-9_-]+\s+\((?:google|gmail)\.com:",
            value,
            re.IGNORECASE,
        )
    ][:1]


def parse_authentication_header(value):
    """Parse authentication methods and their associated result properties."""
    method_pattern = re.compile(
        r"(?:^|;)\s*(spf|dkim|dmarc)\s*=\s*([a-z0-9_-]+)"
        r"(.*?)(?=(?:;\s*[a-z][a-z0-9_-]*\s*=)|$)",
        re.IGNORECASE,
    )
    return [
        {
            "method": match.group(1).lower(),
            "result": match.group(2).lower(),
            "properties": match.group(3),
        }
        for match in method_pattern.finditer(value or "")
    ]


def get_auth_property(properties, *names):
    for name in names:
        pattern = re.compile(
            rf"\b{re.escape(name)}\s*=\s*(?:\"([^\"]*)\"|([^\s;()]+))",
            re.IGNORECASE,
        )
        match = pattern.search(properties or "")
        if match:
            return match.group(1) if match.group(1) is not None else match.group(2)
    return ""


def normalize_domain(value):
    value = (value or "").strip().strip("<>\"'")
    if "@" in value:
        value = value.rsplit("@", 1)[1]
    return value.lower().rstrip(".")


def extract_authentication_results(headers):
    """Extract verdicts plus evaluated SPF, DKIM, and DMARC identities."""
    primary_values, fallback_values = select_authentication_headers(headers)
    parsed_primary = [
        item for value in primary_values for item in parse_authentication_header(value)
    ]
    parsed_fallback = [
        item for value in fallback_values for item in parse_authentication_header(value)
    ]
    selected = {}

    for method in ("spf", "dkim", "dmarc"):
        matches = [item for item in parsed_primary if item["method"] == method]
        if not matches:
            matches = [item for item in parsed_fallback if item["method"] == method]
        selected[method] = matches

    if not selected["spf"]:
        received_spf = get_trusted_received_spf(headers)
        for value in received_spf:
            match = re.match(r"\s*([a-z0-9_-]+)", value, re.IGNORECASE)
            if match:
                selected["spf"].append(
                    {
                        "method": "spf",
                        "result": match.group(1).lower(),
                        "properties": value,
                    }
                )

    def results_for(method):
        return distinct(item["result"] for item in selected[method])

    spf_domains = distinct(
        normalize_domain(
            get_auth_property(
                item["properties"],
                "smtp.mailfrom",
                "envelope-from",
                "smtp.helo",
                "helo",
            )
        )
        for item in selected["spf"]
    )
    dkim_domains = distinct(
        normalize_domain(
            get_auth_property(item["properties"], "header.d", "header.i")
        )
        for item in selected["dkim"]
    )
    dkim_selectors = distinct(
        get_auth_property(item["properties"], "header.s").lower()
        for item in selected["dkim"]
    )
    dmarc_domains = distinct(
        normalize_domain(get_auth_property(item["properties"], "header.from"))
        for item in selected["dmarc"]
    )

    return {
        "spf": serialize_log_list(results_for("spf"), "not_found"),
        "spf_domain": serialize_log_list(spf_domains, "not_found"),
        "dkim": serialize_log_list(results_for("dkim"), "not_found"),
        "dkim_domain": serialize_log_list(dkim_domains, "not_found"),
        "dkim_selector": serialize_log_list(dkim_selectors, "not_found"),
        "dmarc": serialize_log_list(results_for("dmarc"), "not_found"),
        "dmarc_domain": serialize_log_list(dmarc_domains, "not_found"),
    }


def extract_source_ip(headers):
    """Find the SMTP client IP recorded at Gmail's receiving boundary."""
    primary_values, fallback_values = select_authentication_headers(headers)
    candidates = []

    for value in primary_values + fallback_values + get_trusted_received_spf(headers):
        candidates.extend(
            re.findall(
                r"\bclient-ip\s*=\s*\[?(?:ipv6:)?([0-9a-f:.]+)\]?",
                value,
                re.IGNORECASE,
            )
        )

    for value in get_headers(headers, "received"):
        if re.search(r"\bby\s+mx\.google\.com\b", value, re.IGNORECASE):
            candidates.extend(
                re.findall(
                    r"\[(?:ipv6:)?([0-9a-f:.]+)\]",
                    value,
                    re.IGNORECASE,
                )
            )

    for candidate in candidates:
        candidate = re.sub(r"^ipv6:", "", candidate, flags=re.IGNORECASE)
        try:
            return str(ipaddress.ip_address(candidate))
        except ValueError:
            continue
    return "not_found"


def sanitize_log_value(value):
    """Keep each Wazuh event on one parseable key-value log line."""
    value = normalize_whitespace(str(value or ""))
    return value.replace("\\", "/").replace('"', "'")


def serialize_log_list(values, default="none"):
    """Flatten a list while preserving item boundaries in the one-line log."""
    serialized = [
        sanitize_log_value(value).replace("|", "%7C")
        for value in values
        if str(value).strip()
    ]
    return " | ".join(serialized) if serialized else default


def format_local_timestamp(timestamp):
    return timestamp.strftime("%Y-%m-%d %H:%M:%S")


def get_log_file_path():
    """Load the persisted log path or ask for it on the first execution."""
    try:
        config = json.loads(CONFIG_FILE.read_text(encoding="utf-8"))
        saved_path = config.get("log_file", "") if isinstance(config, dict) else ""
        if isinstance(saved_path, str) and saved_path.strip():
            return os.path.expanduser(saved_path.strip())
    except (FileNotFoundError, OSError, json.JSONDecodeError):
        pass

    prompt = f"Log file location [{DEFAULT_LOG_FILE}]: "
    try:
        selected_path = input(prompt).strip().strip('"')
    except EOFError:
        selected_path = ""

    if selected_path:
        log_file_path = os.path.expanduser(selected_path)
        is_windows_absolute = bool(re.match(r"^[a-z]:[\\/]", log_file_path, re.I))
        if not os.path.isabs(log_file_path) and not is_windows_absolute:
            log_file_path = os.path.abspath(log_file_path)
    else:
        log_file_path = DEFAULT_LOG_FILE

    try:
        CONFIG_FILE.write_text(
            json.dumps({"log_file": log_file_path}, indent=2) + "\n",
            encoding="utf-8",
        )
    except OSError as error:
        print(f"Warning: could not save log file configuration: {error}")

    return log_file_path


def fetch_emails():
    log_file_path = get_log_file_path()
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

            try:
                internal_date_ms = int(message["internalDate"])
                received_datetime = datetime.datetime.fromtimestamp(
                    internal_date_ms / 1000.0
                )
                gmail_received_time = format_local_timestamp(received_datetime)
            except (KeyError, TypeError, ValueError, OSError):
                gmail_received_time = "not_found"

            payload = message.get("payload", {})
            headers = payload.get("headers", [])
            subject = get_header(headers, "subject")
            sender = get_header(headers, "from")
            receiver = get_header(headers, "to")
            cc = get_header(headers, "cc", "not_found")
            reply_to = get_header(headers, "reply-to", "not_found")
            return_path = get_header(headers, "return-path", "not_found")
            rfc_message_id = get_header(headers, "message-id", "not_found")
            in_reply_to = get_header(headers, "in-reply-to", "not_found")
            references = serialize_log_list(
                get_headers(headers, "references"),
                "not_found",
            )
            header_date = get_header(headers, "date", "not_found")
            authentication = extract_authentication_results(headers)
            source_ip = extract_source_ip(headers)

            body, urls = extract_content(service, message_id, payload)
            url_domains = distinct(
                urlsplit(url).hostname.lower().rstrip(".")
                for url in urls
                if urlsplit(url).hostname
            )
            attachments = extract_attachment_metadata(payload)

            body = sanitize_log_value(body)
            if len(body) > MAX_BODY_LENGTH:
                body = body[: MAX_BODY_LENGTH - 3] + "..."

            fetch_time = format_local_timestamp(datetime.datetime.now())

            fields = {
                "fetch_time": fetch_time,
                "gmail_received_time": gmail_received_time,
                "header_date": header_date,
                "integration": "gmail",
                "gmail_id": message_id,
                "rfc_message_id": rfc_message_id,
                "thread_id": message.get("threadId", "not_found"),
                "from": sender,
                "to": receiver,
                "cc": cc,
                "reply_to": reply_to,
                "return_path": return_path,
                "in_reply_to": in_reply_to,
                "references": references,
                "subject": subject,
                "spf": authentication["spf"],
                "spf_domain": authentication["spf_domain"],
                "dkim": authentication["dkim"],
                "dkim_domain": authentication["dkim_domain"],
                "dkim_selector": authentication["dkim_selector"],
                "dmarc": authentication["dmarc"],
                "dmarc_domain": authentication["dmarc_domain"],
                "source_ip": source_ip,
                "urls": serialize_log_list(urls),
                "url_domains": serialize_log_list(url_domains),
                "attachment_count": len(attachments),
                "attachment_filenames": serialize_log_list(
                    attachment["filename"] for attachment in attachments
                ),
                "attachment_types": serialize_log_list(
                    attachment["mime_type"] for attachment in attachments
                ),
                "attachment_sizes": serialize_log_list(
                    attachment["size"] for attachment in attachments
                ),
                "body": body,
            }
            log_line = " ".join(
                f'{key}="{sanitize_log_value(value)}"'
                for key, value in fields.items()
            )
            log_file.write(log_line + "\n")


if __name__ == "__main__":
    fetch_emails()
