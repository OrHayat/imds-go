#!/usr/bin/env bash
set -euo pipefail

GO_MIN_VERSION="1.26"
GIT_TOWN_MIN_VERSION="22.0"

version_ge() {
    [ "$(printf '%s\n%s' "$1" "$2" | sort -t. -k1,1n -k2,2n | head -1)" = "$2" ]
}

detect_os() {
    case "$(uname -s)" in
        Linux)  echo "linux" ;;
        Darwin) echo "darwin" ;;
        *)      echo -e "\e[31m[ERROR]\e[0m Unsupported OS: $(uname -s)" >&2; exit 1 ;;
    esac
}

detect_arch() {
    case "$(uname -m)" in
        x86_64)       echo "amd64" ;;
        aarch64|arm64) echo "arm64" ;;
        *)            echo -e "\e[31m[ERROR]\e[0m Unsupported arch: $(uname -m)" >&2; exit 1 ;;
    esac
}

install_go() {
    if command -v go &>/dev/null; then
        local version
        version=$(go version | awk '{print $3}' | tr -d 'go' | cut -d. -f1,2)
        if version_ge "$version" "$GO_MIN_VERSION"; then
            echo -e "\e[32m[OK]\e[0m Go $version"
            return
        fi
        echo -e "\e[33m[UPGRADE]\e[0m Go $version found, need >= $GO_MIN_VERSION"
    else
        echo -e "\e[33m[MISSING]\e[0m Go not found"
    fi

    echo "Installing Go from go.dev..."
    local os arch
    os=$(detect_os)
    arch=$(detect_arch)
    local latest
    latest=$(curl -sL 'https://go.dev/VERSION?m=text' | head -1)
    if ! echo "$latest" | grep -qE '^go[0-9]+\.'; then
        echo -e "\e[31m[ERROR]\e[0m Failed to determine latest Go version"
        exit 1
    fi
    local tmpfile
    tmpfile=$(mktemp /tmp/go-XXXXXX)
    curl -sL "https://go.dev/dl/${latest}.${os}-${arch}.tar.gz" -o "$tmpfile"
    echo "This will replace /usr/local/go"
    sudo rm -rf /usr/local/go
    sudo tar -C /usr/local -xzf "$tmpfile"
    rm -f "$tmpfile"
    export PATH="/usr/local/go/bin:$PATH"
    echo -e "\e[32m[OK]\e[0m Go installed. Add /usr/local/go/bin to your PATH if not already."
}

install_git_town() {
    if command -v git-town &>/dev/null; then
        local version
        version=$(git-town --version 2>&1 | awk '{print $NF}' | cut -d. -f1,2)
        if version_ge "$version" "$GIT_TOWN_MIN_VERSION"; then
            echo -e "\e[32m[OK]\e[0m git-town $version"
            return
        fi
        echo -e "\e[33m[UPGRADE]\e[0m git-town $version found, need >= $GIT_TOWN_MIN_VERSION"
    else
        echo -e "\e[33m[MISSING]\e[0m git-town not found"
    fi

    echo "Installing git-town via go install..."
    go install github.com/git-town/git-town/v22@v22.7.1
    echo -e "\e[32m[OK]\e[0m git-town installed"
}

echo "=== imds-go dev setup ($(uname -s)) ==="
echo ""
install_go
install_git_town
echo ""
echo "Setup complete."
