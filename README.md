# Splunk-to-Splunk Protocol Library

This project is pubilshed under the [Apache License](LICENSE). It was originally based on Splunk's
[eventgen s2s plugin](https://github.com/splunk/eventgen/blob/develop/splunk_eventgen/lib/plugins/output/s2s.py)
which only supports the "older" (version 2) protocol. Packet captures were then used to add support for version 3.
New protocol versions are not currently supported.


## Configuring Universal Forwarders

You can use this to receive events from Splunk's Universal Forwarders. Simply update your `outputs.conf` file:

* Add an additional `tcpout` destination:

```
[tcpout:s2s]
server = [<s2s_ip>|<s2s_host>]:<port>
compressed = false
sendCookedData = true
negotiateProtocolLevel = 0
```

Include `negotiateProtocolLevel = 0` when using Splunk Universal Forwarders older than version 9.1.0.

* Add it to your `[tcpout]` section:

```
[tcpout]
disabled = false
defaultGroup = <splunk_indexers>, s2s, ...
enableOldS2SProtocol = true
```

Include `enableOldS2SProtocol = true` when using Splunk Universal Forwarders version 9.1.0 or later.

See also [this article about best practices](https://cribl.io/blog/better-practices-for-getting-data-in-from-splunk-universal-forwarders/) from Cribl.


## Command Line Tool

The library includes a command-line tool `s2s` that can be used to send log file contents to a Splunk-to-Splunk (S2S) endpoint or run as a server to receive S2S events.

### Usage

```bash
# Client mode (send events)
s2s [options] -file <logfile>

# Server mode (receive events)
s2s -server [options]
```

### Options

#### Common Options
- `-version`: Display the current version of s2s
- `-endpoint <host:port>`: S2S server endpoint (default: localhost:9997)

#### Client Mode Options
- `-file <path>`: Path to the log file to send (required for client mode)
- `-tls`: Enable TLS connection
- `-cert <path>`: Path to client certificate for TLS (optional)
- `-server-name <name>`: Server name for TLS verification
- `-insecure`: Skip TLS certificate verification (not recommended for production)
- `-index <name>`: Index to send events to
- `-host <name>`: Host value for events
- `-source <path>`: Source value for events
- `-sourcetype <type>`: Sourcetype value for events

#### Server Mode Options
- `-server`: Run in server mode (listen for incoming connections)
- `-tls`: Enable TLS for incoming connections
- `-cert <path>`: Path to server certificate file for TLS (required if -tls is set)
- `-key <path>`: Path to server private key file for TLS (required if -tls is set)
- `-insecure`: Skip TLS certificate verification for incoming connections (not recommended for production)

### Examples

#### Client Mode Examples

1. Send log file using plain TCP connection:
   ```bash
   s2s -file /var/log/application.log -endpoint splunk.example.com:9997
   ```

2. Send log file using TLS without client certificate:
   ```bash
   s2s -file /var/log/application.log -endpoint splunk.example.com:9997 -tls
   ```

3. Send log file using TLS with client certificate:
   ```bash
   s2s -file /var/log/application.log -endpoint splunk.example.com:9997 -tls -cert /path/to/cert.pem -server-name splunk.example.com
   ```

4. Send log file using TLS with insecure verification (not recommended for production):
   ```bash
   s2s -file /var/log/application.log -endpoint splunk.example.com:9997 -tls -insecure
   ```

5. Send log file with event metadata:
   ```bash
   s2s -file /var/log/application.log -endpoint splunk.example.com:9997 \
     -index main \
     -host myserver.example.com \
     -source /var/log/application.log \
     -sourcetype myapp
   ```

#### Server Mode Examples

1. Run in server mode (listen for incoming connections):
   ```bash
   s2s -server -endpoint localhost:9997
   ```

2. Run in server mode with TLS:
   ```bash
   s2s -server -endpoint localhost:9997 -tls -cert /path/to/cert.pem -key /path/to/key.pem
   ```

3. Run in server mode with TLS and insecure verification (not recommended for production):
   ```bash
   s2s -server -endpoint localhost:9997 -tls -cert /path/to/cert.pem -key /path/to/key.pem -insecure
   ```

### Notes

#### Client Mode Notes
- The command reads the log file line by line and sends each line as a separate event
- If an error occurs while sending an event, it will be logged but the command will continue processing the remaining events
- The connection is automatically closed when all events have been sent or if an error occurs
- When using TLS, the server name should match the certificate's Common Name (CN) or Subject Alternative Name (SAN)
- Event metadata (index, host, source, sourcetype) is applied to all events sent from the log file
- If metadata fields are not specified, they will be empty in the sent events

#### Server Mode Notes
- In server mode, the command will listen for incoming connections and print each received event to stdout
- Server mode can be stopped by pressing Ctrl+C
- When using TLS in server mode, both certificate (-cert) and private key (-key) files must be specified
- The server validates the S2S protocol signature from incoming connections
- Each client connection is handled in a separate goroutine
- The server will continue accepting new connections until stopped
- Events are printed to stdout in the format: "Received event: <event content>"

