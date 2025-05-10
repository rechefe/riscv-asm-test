#!/bin/bash

# Start the code-server
exec code-server --auth none --bind-addr 0.0.0.0:${VS_CODE_SERVER_PORT} /project.code-workspace