#!/usr/bin/env bash
set -euo pipefail

GO_MIN_VERSION="1.22"
GIT_TOWN_MIN_VERSION="22.0"

compare_version() {
    local current="$1" minimum="$2"
    printf '%s\n%s' "$minimum" "$current" | sort -V -C
}

extract_version() {
    echo "$1" | sed -n 's/.*\([0-9]\+\.[0-9]\+\).*/\1/p' | head -1
}

detect_os() {
    case "$(uname -s)" in
        Linux)  echo "linux" ;;
        Darwin) echo "darwin" ;;
        *)      echo "linux" ;;
    esac
}

detect_arch() {
    case "$(uname -m)" in
        x86_64)  echo "amd64" ;;
        aarch64|arm64) echo "arm64" ;;
        *)       echo "amd64" ;;
    esac
}

install_go() {
    if command -v go &>/dev/null; then
        local version
        version=$(extract_version "$(go version)")
        if compare_version "$version" "$GO_MIN_VERSION"; then
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
    curl -sL "https://go.dev/dl/${latest}.${os}-${arch}.tar.gz" -o /tmp/go.tar.gz
    sudo rm -rf /usr/local/go
    sudo tar -C /usr/local -xzf /tmp/go.tar.gz
    rm /tmp/go.tar.gz
    export PATH="/usr/local/go/bin:$PATH"
    echo -e "\e[32m[OK]\e[0m Go installed. Add /usr/local/go/bin to your PATH if not already."
}

install_git_town() {
    if command -v git-town &>/dev/null; then
        local version
        version=$(extract_version "$(git-town --version 2>&1)")
        if compare_version "$version" "$GIT_TOWN_MIN_VERSION"; then
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
