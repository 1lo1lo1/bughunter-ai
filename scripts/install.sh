#!/usr/bin/env bash
# BugHunter AI — Kali Linux Installer
# Usage: chmod +x install.sh && ./install.sh

set -e

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m'

echo -e "${CYAN}${BOLD}"
cat << 'EOF'
  ██████╗ ██╗   ██╗ ██████╗ ██╗  ██╗██╗   ██╗███╗   ██╗████████╗███████╗██████╗
  ██╔══██╗██║   ██║██╔════╝ ██║  ██║██║   ██║████╗  ██║╚══██╔══╝██╔════╝██╔══██╗
  ██████╔╝██║   ██║██║  ███╗███████║██║   ██║██╔██╗ ██║   ██║   █████╗  ██████╔╝
  ██╔══██╗██║   ██║██║   ██║██╔══██║██║   ██║██║╚██╗██║   ██║   ██╔══╝  ██╔══██╗
  ██████╔╝╚██████╔╝╚██████╔╝██║  ██║╚██████╔╝██║ ╚████║   ██║   ███████╗██║  ██║
  ╚═════╝  ╚═════╝  ╚═════╝ ╚═╝  ╚═╝ ╚═════╝ ╚═╝  ╚═══╝   ╚═╝   ╚══════╝╚═╝  ╚═╝
EOF
echo -e "${NC}"
echo -e "${CYAN}  BugHunter AI — Installer for Kali Linux${NC}"
echo -e "${YELLOW}  Free & Open Source Alternative to Penligent${NC}"
echo ""

# Check OS
if [[ ! -f /etc/os-release ]]; then
    echo -e "${RED}❌ Cannot detect OS${NC}"
    exit 1
fi

OS=$(grep ^ID /etc/os-release | cut -d= -f2 | tr -d '"')
echo -e "${GREEN}✓ OS detected: $OS${NC}"

# Check Python
if ! command -v python3 &>/dev/null; then
    echo -e "${YELLOW}⚠ Python3 not found, installing...${NC}"
    sudo apt-get update -qq && sudo apt-get install -y python3 python3-pip python3-venv
fi

PYTHON_VER=$(python3 --version | cut -d' ' -f2 | cut -d. -f1-2)
echo -e "${GREEN}✓ Python $PYTHON_VER found${NC}"

# Check pip
if ! command -v pip3 &>/dev/null; then
    echo -e "${YELLOW}⚠ pip3 not found, installing...${NC}"
    sudo apt-get install -y python3-pip
fi

# Check git
if ! command -v git &>/dev/null; then
    echo -e "${YELLOW}⚠ git not found, installing...${NC}"
    sudo apt-get install -y git
fi

echo ""
echo -e "${CYAN}📦 Installing BugHunter AI...${NC}"

# Install in user space (no sudo needed)
pip3 install --user --break-system-packages -e . 2>/dev/null || \
pip3 install --user -e . 2>/dev/null || \
pip3 install -e .

# Check if bughunter is in PATH
if ! command -v bughunter &>/dev/null; then
    echo -e "${YELLOW}⚠ Adding ~/.local/bin to PATH...${NC}"
    echo 'export PATH="$HOME/.local/bin:$PATH"' >> ~/.bashrc
    echo 'export PATH="$HOME/.local/bin:$PATH"' >> ~/.zshrc 2>/dev/null || true
    export PATH="$HOME/.local/bin:$PATH"
fi

echo ""
echo -e "${GREEN}${BOLD}✅ Installation complete!${NC}"
echo ""
echo -e "${CYAN}Usage:${NC}"
echo -e "  ${BOLD}bughunter scan ./myapp/${NC}              # Basic scan"
echo -e "  ${BOLD}bughunter scan ./myapp/ --ai${NC}         # AI-powered scan (requires Ollama or API key)"
echo -e "  ${BOLD}bughunter scan ./myapp/ --format html --output report.html${NC}"
echo -e "  ${BOLD}bughunter interactive${NC}                # Guided mode"
echo -e "  ${BOLD}bughunter --help${NC}                     # Full help"
echo ""
echo -e "${YELLOW}💡 For FREE local AI (no API key needed):${NC}"
echo -e "  curl -fsSL https://ollama.ai/install.sh | sh"
echo -e "  ollama pull llama3"
echo -e "  bughunter scan ./myapp/ --ai --model ollama:llama3"
echo ""
echo -e "${CYAN}GitHub: https://github.com/YOUR_USERNAME/bughunter-ai${NC}"
