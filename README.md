# Gmail Extraction and Wazuh Integration

This project collects recent unread Gmail messages through the Gmail API and
writes them as single-line events for Wazuh. Wazuh can then collect, decode,
and classify alerts generated from those events.

```text
Gmail API -> fetch_gmail.py -> gmail_security.log -> Wazuh agent
          -> Wazuh manager decoder -> phishing rules -> Wazuh alert
```

The script uses read-only Gmail access. It does not modify messages or mark
them as read.

## Features

- Fetches unread messages received within the last five minutes
- Extracts sender, recipient, reply, routing, thread, and message identifiers
- Collects SPF, DKIM, and DMARC verdicts, domains, and the DKIM selector
- Extracts web URLs and their domains before the body is truncated
- Records attachment filenames, MIME types, and sizes without downloading them
- Handles plain-text and HTML email bodies
- Preserves useful links found in HTML messages
- Retrieves attachment-backed text when Gmail stores body content separately
- Normalizes values into one-line events suitable for Wazuh
- Limits logged message bodies to 2,000 characters

## 1. Host/Endpoint Installation

The Gmail collector runs on the Windows host where the Wazuh agent is
installed.

### Requirements

- Python 3.8 or later
- A Google account with Gmail
- A Google Cloud project with the Gmail API enabled
- OAuth 2.0 desktop application credentials
- A Wazuh agent, when using the default output path

### Install the collector

Clone or download this project, open PowerShell in the project directory, and
create a virtual environment:

```powershell
py -m venv .venv
.venv\Scripts\Activate.ps1
python -m pip install -r requirements.txt
```

### Configure Google OAuth

1. Create or select a project in Google Cloud Console.
2. Enable the Gmail API for the project.
3. Configure the OAuth consent screen. If the application is in testing mode,
   add the Gmail account that will run the collector as a test user.
4. Create an OAuth client ID for a **Desktop app**.
5. Download the client credentials, rename the file to `credentials.json`, and
   place it in the project directory beside `fetch_gmail.py`.

Do not commit `credentials.json` or `token.json`. Both contain sensitive
authentication information.

### Collector configuration

The default settings are defined near the top of `fetch_gmail.py`:

```python
DEFAULT_LOG_FILE = (
    r"C:\Program Files (x86)\ossec-agent\active-response\gmail_security.log"
)
TOKEN_FILE = "token.json"
CREDENTIALS_FILE = "credentials.json"
CONFIG_FILE = Path(__file__).resolve().with_name("config.json")
LOOKBACK_SECONDS = 5 * 60
MAX_BODY_LENGTH = 2000
```

On each run, the collector builds an `is:unread after:<epoch>` Gmail query using
the current time minus `LOOKBACK_SECONDS`. This provides a true five-minute
window; Gmail's `newer_than` operator does not support minutes. Because the
collector has read-only access, running it more than once during that window
can log the same message again.

### Run and authorize the collector

Run the script from the project directory:

```powershell
python fetch_gmail.py
```

On the first execution, the collector asks where it should write the log:

```text
Log file location [C:\Program Files (x86)\ossec-agent\active-response\gmail_security.log]:
```

Press Enter to use the Wazuh agent path shown in brackets, or enter another
path. The selected directory must already exist, and the account running the
collector must be allowed to append to the file. Relative paths are converted
to absolute paths.

The selection is stored in `config.json` beside the script. Later executions
load it without prompting. To select a different location, delete `config.json`
and run the collector again, or edit its `log_file` value directly:

```json
{
  "log_file": "C:\\Program Files (x86)\\ossec-agent\\active-response\\gmail_security.log"
}
```

`config.json` is machine-specific and excluded from Git.

On the first run, a browser opens for Google authorization. The resulting
credentials are stored in `token.json` for later runs. If no messages match
the Gmail query, the collector exits without adding an event.

Each collected message has this format (shortened here for readability):

```text
fetch_time="2026-07-19 11:30:00" gmail_received_time="2026-07-19 11:29:00" header_date="Sun, 19 Jul 2026 11:28:50 +0700" integration="gmail" gmail_id="18f..." rfc_message_id="<message@example.com>" thread_id="18f..." from="Sender <sender@example.com>" to="recipient@example.com" cc="not_found" reply_to="reply@example.com" return_path="<bounce@example.com>" in_reply_to="not_found" references="not_found" subject="Example" spf="pass" spf_domain="example.com" dkim="pass" dkim_domain="example.com" dkim_selector="selector1" dmarc="pass" dmarc_domain="example.com" source_ip="203.0.113.10" urls="https://example.com/login" url_domains="example.com" attachment_count="0" attachment_filenames="none" attachment_types="none" attachment_sizes="none" body="Message text [Link: https://example.com/login]"
```

`gmail_received_time` comes from Gmail's internal timestamp and uses the
endpoint's local time zone. `header_date` retains the date claimed by the
sender. Whitespace, backslashes, and double quotes in values are normalized so
each event stays on one line.

Authentication data is read from Gmail's `mx.google.com`
`Authentication-Results` when available, with `ARC-Authentication-Results` and
`Received-SPF` as fallbacks. The collector also records the SPF mail-from
domain, DKIM signing domain and selector, DMARC header-from domain, and the
client IP observed at Gmail's receiving boundary.

URLs are collected from plain text, visible HTML text, and HTML `href`, `src`,
and `action` attributes before the body is limited to 2,000 characters.
Attachment contents are not downloaded; the collector reads only the filename,
MIME type, and declared byte size already present in the Gmail message payload.
Multiple values are separated with ` | `. Missing optional headers and
authentication values are logged as `not_found`; empty lists use `none`.

### Schedule collection

Use Windows Task Scheduler to run the collector periodically. Configure the
task to:

- run as an account with access to the OAuth files and Wazuh log directory;
- start the virtual environment's `python.exe`;
- pass the absolute path to `fetch_gmail.py` as an argument; and
- use the project directory as the working directory.

Authorize the collector and select its log path interactively before enabling
the scheduled task. Subsequent unattended runs use the location saved in
`config.json`. If the first execution is unattended and standard input reaches
EOF, the default Wazuh path is selected and saved automatically.

## 2. Wazuh Agent and Server Integration

This section configures the endpoint agent to collect the Gmail event file and
the Wazuh manager to decode it and apply phishing rules.

### Configure log collection on the Wazuh agent

On the Windows endpoint, add the following block inside the existing
`<ossec_config>` element in:

`C:\Program Files (x86)\ossec-agent\ossec.conf`

```xml
<!-- Gmail Collection-->
<localfile>
  <log_format>syslog</log_format>
  <location>C:\Program Files (x86)\ossec-agent\active-response\gmail_security.log</location>
</localfile>
```

The `<location>` value must match the path selected when running the Gmail
collector. Save the file and restart the Wazuh agent so it reloads the
configuration.

### Add the Gmail decoders on the Wazuh manager

Add these decoders to `/var/ossec/etc/decoder/local_decoder.xml`:

```xml
<decoder name="gmail-custom">
  <prematch>integration="gmail"</prematch>
</decoder>

<decoder name="gmail-custom-fields">
  <parent>gmail-custom</parent>
  <regex type="pcre2">fetch_time="([^"]*)"\s+gmail_received_time="([^"]*)"\s+header_date="([^"]*)"\s+integration="gmail"\s+gmail_id="([^"]*)"\s+rfc_message_id="([^"]*)"\s+thread_id="([^"]*)"\s+from="([^"]*)"\s+to="([^"]*)"\s+cc="([^"]*)"\s+reply_to="([^"]*)"\s+return_path="([^"]*)"\s+in_reply_to="([^"]*)"\s+references="([^"]*)"\s+subject="([^"]*)"\s+spf="([^"]*)"\s+spf_domain="([^"]*)"\s+dkim="([^"]*)"\s+dkim_domain="([^"]*)"\s+dkim_selector="([^"]*)"\s+dmarc="([^"]*)"\s+dmarc_domain="([^"]*)"\s+source_ip="([^"]*)"\s+urls="([^"]*)"\s+url_domains="([^"]*)"\s+attachment_count="([^"]*)"\s+attachment_filenames="([^"]*)"\s+attachment_types="([^"]*)"\s+attachment_sizes="([^"]*)"\s+body="([^"]*)"</regex>
  <order>gmail_fetch_time, gmail_received_time, gmail_header_date, gmail_id, gmail_rfc_message_id, gmail_thread_id, gmail_from, gmail_to, gmail_cc, gmail_reply_to, gmail_return_path, gmail_in_reply_to, gmail_references, gmail_subject, gmail_spf, gmail_spf_domain, gmail_dkim, gmail_dkim_domain, gmail_dkim_selector, gmail_dmarc, gmail_dmarc_domain, gmail_source_ip, gmail_urls, gmail_url_domains, gmail_attachment_count, gmail_attachment_filenames, gmail_attachment_types, gmail_attachment_sizes, gmail_body</order>
</decoder>
```

The parent decoder identifies events containing `integration="gmail"`. The
child decoder extracts the Gmail fields used by the rules. Each quoted capture
accepts an empty value so one unavailable header cannot prevent the rest of the
event from being decoded.

This decoder replaces the earlier version because `sent_time` is now the more
accurately named `gmail_received_time`, `id` is now `gmail_id`, and the new
investigation fields occur between those values and the body.

### Add the phishing detection rules

Create `/var/ossec/etc/rules/gmail_phishing.xml` with:

```xml
<group name="gmail,phishing,">
  <rule id="100300" level="3">
    <decoded_as>gmail-custom</decoded_as>
    <description>Gmail monitoring: New message parsed.</description>
  </rule>

  <rule id="100301" level="7">
    <if_sid>100300</if_sid>
    <field name="gmail_subject" type="pcre2">(?i)(urgent|action required|verify|suspicious login|password reset|invoice)</field>
    <description>Gmail Phishing Alert: High-risk urgency keyword detected in email subject.</description>
    <mitre>
      <id>T1566.001</id>
    </mitre>
  </rule>
</group>
```

Rule `100300` records successfully decoded Gmail messages at level 3. Rule
`100301` raises the level to 7 when the subject contains one of the configured
high-risk keywords and maps the alert to MITRE ATT&CK technique T1566.001.

After installing the decoder and rules, validate the manager configuration and
restart the Wazuh manager. Generate or receive a test email with a subject such
as `Urgent: verify invoice`, run the collector, and confirm the full flow:

1. A new line appears in `gmail_security.log` on the endpoint.
2. The Wazuh agent forwards the line to the manager.
3. The `gmail-custom` decoder extracts the Gmail fields.
4. Rule `100300` matches the message and rule `100301` detects the keyword.

## Security Notes

- The OAuth scope is limited to `gmail.readonly`.
- Email bodies and Wazuh alerts can contain sensitive information; restrict
  access to both.
- Protect `credentials.json` and `token.json` with appropriate file
  permissions.
- Revoke the application's Google account access if a token is exposed.

## License

This project is licensed under the terms in [LICENSE](LICENSE).
