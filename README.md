# Gmail Extraction and Wazuh Integration

This project collects recent unread Gmail messages through the Gmail API and
writes them as single-line events for Wazuh. Wazuh can then collect, decode,
classify, and deliver alerts generated from those events.

```text
Gmail API -> fetch_gmail.py -> gmail_security.log -> Wazuh agent
          -> Wazuh manager decoder -> phishing rules -> alert integration
```

The script uses read-only Gmail access. It does not modify messages or mark
them as read.

## Features

- Fetches unread messages received within the last five minutes
- Extracts sender, recipient, subject, Gmail message ID, and timestamps
- Collects SPF, DKIM, and DMARC authentication results
- Handles plain-text and HTML email bodies
- Preserves useful links found in HTML messages
- Retrieves text MIME parts stored by Gmail as attachments
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
GMAIL_QUERY = "is:unread newer_than:5m"
MAX_BODY_LENGTH = 2000
```

`GMAIL_QUERY` accepts Gmail search syntax. The default query selects unread
mail from the last five minutes. Because the collector has read-only access,
running it more than once during that window can log the same message again.

### Run and authorize the collector

Run the script from the project directory:

```powershell
python fetch_gmail.py
```

The collector asks where it should write the log:

```text
Log file location [C:\Program Files (x86)\ossec-agent\active-response\gmail_security.log]:
```

Press Enter to use the Wazuh agent path shown in brackets, or enter another
path. The selected directory must already exist, and the account running the
collector must be allowed to append to the file.

On the first run, a browser opens for Google authorization. The resulting
credentials are stored in `token.json` for later runs. If no messages match
the Gmail query, the collector exits without adding an event.

Each collected message has this format:

```text
fetch_time="2026-07-19 11:30:00" sent_time="2026-07-19 11:29:00" integration="gmail" id="18f..." from="sender@example.com" to="recipient@example.com" subject="Example" spf="pass" dkim="pass" dmarc="pass" body="Message text [Link: https://example.com]"
```

The timestamps use the endpoint's local time zone. Whitespace, backslashes,
and double quotes in field values are normalized to keep each event on one
line. Authentication results are read from `Authentication-Results`, with
`ARC-Authentication-Results` and `Received-SPF` used as fallbacks. A missing
verdict is logged as `not_found`; multiple distinct verdicts are comma-separated.

### Schedule collection

Use Windows Task Scheduler to run the collector periodically. Configure the
task to:

- run as an account with access to the OAuth files and Wazuh log directory;
- start the virtual environment's `python.exe`;
- pass the absolute path to `fetch_gmail.py` as an argument; and
- use the project directory as the working directory.

An unattended run receives no interactive input, so the collector uses the
default Wazuh log path when standard input reaches EOF.

## 2. Wazuh Agent, Server Integration, and Delivery

This section configures the endpoint agent to collect the Gmail event file and
the Wazuh manager to decode it, apply phishing rules, and pass selected alerts
to a custom delivery integration.

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
  <regex type="pcre2">sent_time="([^"]+)"\s+integration="gmail"\s+id="([^"]+)"\s+from="([^"]+)"\s+to="([^"]+)"\s+subject="([^"]+)"\s+spf="([^"]+)"\s+dkim="([^"]+)"\s+dmarc="([^"]+)"\s+body="([^"]+)"</regex>
  <order>gmail_sent_time, gmail_id, gmail_from, gmail_to, gmail_subject, gmail_spf, gmail_dkim, gmail_dmarc, gmail_body</order>
</decoder>
```

The parent decoder identifies events containing `integration="gmail"`. The
child decoder extracts the Gmail fields used by the rules.

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

### Configure alert delivery

Add the delivery integration to the Wazuh manager's
`/var/ossec/etc/ossec.conf`:

```xml
<integration>
  <name>integration-script.py</name>
  <rule_id>100302, 100303</rule_id> 
  <alert_format>json</alert_format>
</integration>
```

The delivery script must be installed in the manager's Wazuh integrations
directory, have the name referenced by `<name>`, and be executable by Wazuh.
The manager passes matching alerts to it as JSON.

> **Rule ID check:** The supplied delivery configuration listens for rules
> `100302` and `100303`, while the Gmail rules above define `100300` and
> `100301`. If `100302` and `100303` are not defined elsewhere, change
> `<rule_id>` to `100300,100301` to deliver the alerts created by this ruleset.

After installing the decoder, rules, and integration, validate the manager
configuration and restart the Wazuh manager. Generate or receive a test email
with a subject such as `Urgent: verify invoice`, run the collector, and confirm
the full flow:

1. A new line appears in `gmail_security.log` on the endpoint.
2. The Wazuh agent forwards the line to the manager.
3. The `gmail-custom` decoder extracts the Gmail fields.
4. Rule `100300` matches the message and rule `100301` detects the keyword.
5. The configured delivery integration receives the matching JSON alert.

## Security Notes

- The OAuth scope is limited to `gmail.readonly`.
- Email bodies and Wazuh alerts can contain sensitive information; restrict
  access to both.
- Protect `credentials.json` and `token.json` with appropriate file
  permissions.
- Revoke the application's Google account access if a token is exposed.

## License

This project is licensed under the terms in [LICENSE](LICENSE).
