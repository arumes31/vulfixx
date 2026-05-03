#!/bin/sh

# Start Tor in the background
echo "Starting Tor..."
# (24) Configure Bridges if provided
if [ -n "$TOR_BRIDGES" ]; then
    echo "Configuring Tor Bridges..."
    echo "UseBridges 1" >> /etc/tor/torrc
    echo "ClientTransportPlugin obfs4 exec /usr/bin/obfs4proxy" >> /etc/tor/torrc
    # TOR_BRIDGES should be a newline separated list of bridge lines
    echo "$TOR_BRIDGES" >> /etc/tor/torrc
fi
tor -f /etc/tor/torrc &

# Wait for Tor to initialize
MAX_WAIT=60
COUNT=0
echo "Waiting for Tor to open SOCKS port 9050..."
while ! nc -z 127.0.0.1 9050; do
  sleep 1
  COUNT=$((COUNT+1))
  if [ $((COUNT % 5)) -eq 0 ]; then
     echo "Still waiting for Tor... ($COUNT/$MAX_WAIT)"
  fi
  if [ $COUNT -ge $MAX_WAIT ]; then
    echo "CRITICAL: Tor failed to start within $MAX_WAIT seconds"
    # Show what's listening
    netstat -ant
    exit 1
  fi
done

echo "SUCCESS: Tor is up and running on port 9050."
echo "Starting Scalper..."

# Start the Go process as the non-root user
exec su-exec scalper ./scalper
