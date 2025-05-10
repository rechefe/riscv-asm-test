ARG DEBIAN_VERSION=stable-20241016-slim
ARG VS_CODE_SERVER_VERSION=4.93.1
ARG VS_CODE_SERVER_PORT=8800
ARG VS_CODE_EXT_CPPTOOLS_VERSION=1.22.10
ARG VS_CODE_EXT_HEX_EDITOR_VERSION=1.11.1
ARG VS_CODE_EXT_CMAKETOOLS_VERSION=1.19.52

FROM debian:${DEBIAN_VERSION}

ARG VS_CODE_SERVER_VERSION
ARG VS_CODE_SERVER_PORT
ARG VS_CODE_EXT_CPPTOOLS_VERSION
ARG VS_CODE_EXT_HEX_EDITOR_VERSION
ARG VS_CODE_EXT_CMAKETOOLS_VERSION

# Set non-interactive frontend
ENV DEBIAN_FRONTEND=noninteractive

# Install dependencies
RUN apt-get update && apt-get install -y \
    dos2unix \
    build-essential \
    git \
    wget \
    curl \
    cmake \
    python3 \
    python3-pip \
    python3-setuptools \
    python3-venv \
    libglib2.0-dev \
    pkg-config \
    libtool \
    autoconf \
    automake \
    flex \
    bison \
    libncurses5-dev \
    libexpat1-dev \
    zlib1g-dev \
    unicorn \
    && rm -rf /var/lib/apt/lists/*

# Set up a Python virtual environment
ENV VIRTUAL_ENV=/opt/venv
RUN python3 -m venv ${VIRTUAL_ENV}
ENV PATH="${VIRTUAL_ENV}/bin:$PATH"

# Install Python packages
RUN pip3 install --upgrade pip \
    && pip3 install pytest unicorn

ENV VS_CODE_SERVER_VERSION=${VS_CODE_SERVER_VERSION}
ENV VS_CODE_SERVER_PORT=${VS_CODE_SERVER_PORT}

# Install VS Code Server
RUN cd /tmp && \
    wget ${WGET_ARGS} https://code-server.dev/install.sh && \
    chmod +x install.sh && \
    bash install.sh --version ${VS_CODE_SERVER_VERSION}

# Download VS Code extensions (code-server extension manager does not work well)
RUN cd /tmp && \
    wget ${WGET_ARGS} https://github.com/microsoft/vscode-cpptools/releases/download/v${VS_CODE_EXT_CPPTOOLS_VERSION}/cpptools-linux-x64.vsix -O cpptools.vsix; \
    wget ${WGET_ARGS} https://github.com/microsoft/vscode-cmake-tools/releases/download/v${VS_CODE_EXT_CMAKETOOLS_VERSION}/cmake-tools.vsix -O cmake-tools.vsix && \
    wget --compression=gzip ${WGET_ARGS} https://marketplace.visualstudio.com/_apis/public/gallery/publishers/ms-vscode/vsextensions/hexeditor/${VS_CODE_EXT_HEX_EDITOR_VERSION}/vspackage -O hexeditor.vsix

# Install extensions
RUN cd /tmp && \
    code-server --install-extension cpptools.vsix && \
    code-server --install-extension cmake-tools.vsix && \
    code-server --install-extension hexeditor.vsix

# Clean up
RUN cd /tmp && \
    rm install.sh && \
    rm cpptools.vsix && \
    rm cmake-tools.vsix && \
    rm hexeditor.vsix

# Copy workspace configuration
COPY scripts/project.code-workspace /project.code-workspace

#-------------------------------------------------------------------------------
# Entrypoint

# Activate the Python and Zephyr environments for shell sessions
RUN echo "source ${VIRTUAL_ENV}/bin/activate" >> /root/.bashrc 

# Custom entrypoint
COPY scripts/entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh && \
    dos2unix /entrypoint.sh
ENTRYPOINT ["/entrypoint.sh"]
