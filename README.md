# Integrating Wazuh with MISP Threat Intelligence

|Tested Version|OS|Installation|
|---|---|---|
|4.14.1|Amazon Linux|OVA|


## Objective

Pull IOC data from the MISP database, store it on the Wazuh manager in SQLite databases, and query those databases when alerts are generated.
Relevant fields (such as srcip, dstip, hashes, domains, URLs, etc.) are extracted from alerts and compared against the local IOC database. If a match is found, a new alert is triggered on the Wazuh dashboard.

<img width="887" height="1878" alt="image" src="https://github.com/user-attachments/assets/4a67f319-9b2b-408b-a5d5-dc88728c0b49" />


### Steps
#### Step 1 — Configure the MISP Server
Set up and configure the MISP server. Generate an API key that will be used to pull IOCs.
Refer to the official MISP documentation for installation and configuration guidance.

#### Step 2 — Install Required Packages
Required tools:
- sqlite3
- jq
- python3

For Amazon Linux:
```bash
sudo yum install -y sqlite jq python3-pip
```
Use the appropriate package manager for your Wazuh manager OS.

#### Step 3 — Sync IOCs from MISP to SQLite
3.1 Create Sync Script
```bash
vi /var/ossec/integrations/misp_to_sqlite_sync.py 
```
Paste the `misp_to_sqlite_sync.py` script.

Set permissions:
```bash
chmod 750 /var/ossec/integrations/misp_to_sqlite_sync.py
chown root:wazuh /var/ossec/integrations/misp_to_sqlite_sync.py
```

3.2 Create Environment Configuration
```bash
sudo vi /etc/default/misp-ioc-sync
```
```bash
MISP_URL="https://<MISP-Server-IP>"
MISP_API_KEY="YOUR_ROTATED_KEY"
MISP_VERIFY_SSL="false"

MISP_USE_TIMESTAMP_FILTER="true"
MISP_LAST_N_DAYS="3"

MISP_TO_IDS_ONLY="false"
MISP_PUBLISHED_ONLY="false"
MISP_TAG_FILTER=""

MISP_LIMIT="500"
MISP_MAX_PAGES="200"

IPS_DB_PATH="/var/ioc/ips.db"
HASHES_DB_PATH="/var/ioc/hashes.db"
DOMAINS_DB_PATH="/var/ioc/domains.db"
URLS_DB_PATH="/var/ioc/urls.db"

MISP_SYNC_LOG="/var/ossec/logs/misp-sync.log"
MISP_SYNC_LOG_ENABLED="true"
MISP_SUPPRESS_TLS_WARN="true"
```
Replace:
- `<MISP-Server-IP>` → MISP server address
- `YOUR_ROTATED_KEY` → API key

> **Performance Note**: 
`MISP_LIMIT` and `MISP_MAX_PAGES` control data volume.
Higher values increase resource consumption and may impact performance.

3.3 Create Systemd Service
```bash
sudo vi /etc/systemd/system/misp-ioc-sync.service
```
```bash
[Unit]
Description=MISP IOC SQLite Sync
After=network-online.target
Wants=network-online.target

[Service]
Type=oneshot
User=wazuh
Group=wazuh

EnvironmentFile=/etc/default/misp-ioc-sync

ExecStart=/var/ossec/framework/python/bin/python3 /var/ossec/integrations/misp_to_sqlite_sync.py

Nice=10
IOSchedulingClass=best-effort
IOSchedulingPriority=7

StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
```

3.4 Create Timer
```bash
sudo vi /etc/systemd/system/misp-ioc-sync.timer
```
```bash
[Unit]
Description=Run MISP IOC Sync every hour

[Timer]
OnBootSec=5min
OnUnitActiveSec=1h
AccuracySec=1min
Persistent=true

[Install]
WantedBy=timers.target
```
Adjust sync frequency as needed by change the value of `OnUnitActiveSec`(e.g., 12h).

Enable timer:
```bash
sudo systemctl daemon-reexec
sudo systemctl daemon-reload
sudo systemctl enable --now misp-ioc-sync.timer
```

#### Step 4 — Alert Enrichment Integration

4.1 Create Alert Processing Script
```bash
vi /var/ossec/integrations/custom-misp.py
```
Paste custom-misp.py.

Set permissions:
```bash
chmod 750 /var/ossec/integrations/custom-misp.py
chown root:wazuh /var/ossec/integrations/custom-misp.py
```

4.2 Configure Integration

Edit: `/var/ossec/etc/ossec.conf`

Add:
<integration>
  <name>custom-misp.py</name>
  <level>10</level>
  <alert_format>json</alert_format>
</integration>
This triggers the script for alerts with rule level ≥ 10.
You can refer this [Wazuh documentation](https://documentation.wazuh.com/current/user-manual/manager/integration-with-external-apis.html#custom-integration) for more detaisdl.

4.3 Add Detection Rule
```bash
<group name="misp, threatintel">
  <rule id="101080" level="12">
    <decoded_as>json</decoded_as>
    <field name="integration">ioc_sqlite</field>
    <description>MISP: Found $(ioc.hit.ip.field_matched): $(ioc.hit.ip.indicator) in  MISP databasse</description>
  </rule>
</group>
```
4.4 Restart Manager
```bash
systemctl restart wazuh-manager
```

## Conclusion

After completing this configuration:
- IOC data is synchronized from MISP into local SQLite databases
- Alerts (level ≥ 10) trigger field extraction
- Extracted values are compared against stored IOCs
- Matches generate enriched alerts in the Wazuh dashboard

This approach reduces external API calls, improves enrichment speed, and allows offline threat intelligence matching.
