#!/bin/bash
cat <<'EOF' | sudo tee /etc/systemd/system/nginx.service.d/override.conf > /dev/null
[Service]
LimitNOFILE=1048576
EOF
sudo systemctl daemon-reload

