## 📑 **Filebeat Configuration Documentation**

This guide explains how to configure **Filebeat** to forward Wazuh logs (`/var/ossec/logs/api.log`) to **OpenSearch**, using SSL for secure communication and configuring log parsing for optimal log management and visualization.

---

### 1️⃣ **OpenSearch Output Configuration**

🔑 **Description**: Filebeat forwards logs to an OpenSearch instance over HTTPS, using SSL certificates for secure communication.

🛠 **Configuration**:

```yaml
output.elasticsearch.hosts:
  - 127.0.0.1:9200  # OpenSearch host
# Uncomment additional hosts for a cluster setup
#  - <elasticsearch_ip_node_2>:9200
#  - <elasticsearch_ip_node_3>:9200

output.elasticsearch:
  protocol: https
  username: ${username}               # OpenSearch username
  password: ${password}               # OpenSearch password
  ssl.certificate_authorities:
    - /etc/filebeat/certs/root-ca.pem   # CA certificate file
  ssl.certificate: "/etc/filebeat/certs/wazuh-server.pem"   # SSL certificate
  ssl.key: "/etc/filebeat/certs/wazuh-server-key.pem"       # Private key
```

🔒 **Notes**:
- Replace `${username}` and `${password}` with your OpenSearch credentials.
- SSL certificates must be properly configured to ensure secure communication.

---

### 2️⃣ **Template Configuration**

🧩 **Description**: Defines the template for indexing the logs in OpenSearch, using custom settings and disabling Index Lifecycle Management (ILM).

⚙️ **Configuration**:

```yaml
setup.template.json.enabled: true
setup.template.json.path: '/etc/filebeat/wazuh-template.json'  # Path to template
setup.template.json.name: 'wazuh'
setup.ilm.overwrite: true  # Disable ILM (Index Lifecycle Management)
setup.ilm.enabled: false
```

📝 **Note**:
- The template is crucial to ensure logs are indexed correctly.

---

### 3️⃣ **Input Configuration for Wazuh Logs**

📂 **Description**: Filebeat monitors and parses the Wazuh API log file (`/var/ossec/logs/api.log`), handling multiline logs properly.

🔧 **Configuration**:

```yaml
filebeat.inputs:
  - type: log
    enabled: true
    paths:
      - /var/ossec/logs/api.log   # Path to the Wazuh API log file
    fields:
      log_type: "ossec-api-log"   # Custom field for log identification
    fields_under_root: true
    multiline.pattern: '^\d{4}/\d{2}/\d{2} \d{2}:\d{2}:\d{2}'  # Multiline logs pattern
    multiline.negate: true
    multiline.match: after
```

🛠 **Key Points**:
- **Multiline Pattern**: Ensures logs that span multiple lines are processed correctly.
- **Fields**: Add custom fields such as `log_type` for easier identification in OpenSearch.

---

### 4️⃣ **Log Parsing and Processing**

🧑‍💻 **Description**: Dissects logs for structured storage and renames fields for easier querying and analysis in OpenSearch.

🔧 **Configuration**:

```yaml
processors:
  - dissect:
      tokenizer: "%{timestamp} %{loglevel}: %{user} %{ip} \"%{method} %{endpoint}\" with parameters %{parameters} and body %{body} done in %{duration}s: %{status_code}"
      field: "message"   # Parsing the 'message' field
      target_prefix: "parsed"
  - rename:
      fields:
        - from: "parsed.timestamp"
          to: "event.timestamp"
        - from: "parsed.loglevel"
          to: "log.level"
        - from: "parsed.user"
          to: "user.name"
        - from: "parsed.ip"
          to: "client.ip"
        - from: "parsed.method"
          to: "http.request.method"
        - from: "parsed.endpoint"
          to: "url.path"
        - from: "parsed.status_code"
          to: "http.response.status_code"
```

🔍 **Key Points**:
- **Dissect Processor**: Breaks down the log message into useful fields.
- **Rename Processor**: Maps fields to common OpenSearch field names (e.g., `client.ip`, `log.level`, etc.).

---

### 5️⃣ **Wazuh Module Configuration**

🛡 **Description**: Enables the Wazuh Filebeat module for processing and forwarding Wazuh alerts.

🛠 **Configuration**:

```yaml
filebeat.modules:
  - module: wazuh
    alerts:
      enabled: true   # Capture Wazuh alerts
    archives:
      enabled: false  # Archives are disabled
```

🔧 **Key Points**:
- Alerts from Wazuh are forwarded directly to OpenSearch for monitoring.

---

### 6️⃣ **Filebeat Logging Configuration**

📊 **Description**: Configures Filebeat logging to capture its own activity.

🔧 **Configuration**:

```yaml
logging.level: info  # Set logging level
logging.to_files: true  # Enable logging to files
logging.files:
  path: /var/log/filebeat   # Filebeat log path
  name: filebeat            # Log file name
  keepfiles: 7              # Number of logs to retain
  permissions: 0644         # File permissions
```

---

### 7️⃣ **Security Settings: Seccomp**

🔒 **Description**: Restricts system calls using seccomp for enhanced security.

🔧 **Configuration**:

```yaml
seccomp:
  default_action: allow
  syscalls:
    - action: allow
      names:
        - rseq  # Enable the 'rseq' syscall
```

---

### Steps to Implement the Configuration:

1. **🛠 Install Filebeat**:
   - Follow the [official installation guide](https://www.elastic.co/guide/en/beats/filebeat/current/filebeat-installation.html) for your OS.

2. **⚙️ Configure Filebeat**:
   - Update your `filebeat.yml` file with the provided configuration.

3. **✅ Test Configuration**:
   - Run the following to test:
     ```bash
     sudo filebeat test config
     ```

4. **🚀 Start Filebeat**:
   - Start Filebeat:
     ```bash
     sudo systemctl start filebeat
     sudo systemctl enable filebeat
     ```

5. **🔍 Verify Logs in OpenSearch**:
   - Check OpenSearch Dashboards or use the Dev Tools to ensure logs are being indexed.

6. **📊 Create Index Patterns**:
   - In OpenSearch Dashboards, create an index pattern for `filebeat-*` to visualize the data.
