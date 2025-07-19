# Copyright (c) 2025 Zededa, Inc.
# SPDX-License-Identifier: Apache-2.0

FROM paulzededa/eve-vector:no-lua

RUN apk add --no-cache inotify-tools=4.23.9.0-r0

COPY etc/vector.yaml /etc/vector/vector.yaml
COPY entrypoint.sh /usr/local/bin/entrypoint.sh
RUN chmod +x /usr/local/bin/entrypoint.sh

ENTRYPOINT ["/usr/local/bin/entrypoint.sh"]
