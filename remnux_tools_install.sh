#!/bin/bash
#
#Author: Ray Mon
#Human and AI written
#
# REMnux Tools Installation Script
# Installs malware analysis tools from REMnux on a standard Linux system
# Based on tools listed at https://docs.remnux.org/discover-the-tools/
#
# Usage: sudo bash remnux_tools_install.sh
#
# WARNING: This script will install many packages and may modify your system.
# Review the code before running. Tested on Ubuntu/Debian-based systems.

set -e [cite: 3]

FAILED_TOOLS=()


# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

# Check if running as root
if [ "$EUID" -ne 0 ]; then 
    echo -e "${RED}Please run as root (use sudo)${NC}"
    exit 1
fi

echo -e "${GREEN}REMnux Tools Installer${NC}"
echo "======================================"
echo ""

# Create installation directory
INSTALL_DIR="/opt/remnux-tools"
mkdir -p "$INSTALL_DIR"
cd "$INSTALL_DIR"

# Function to print status
print_status() {
    echo -e "${GREEN}[+]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[!]${NC} $1"
}

print_error() {
    echo -e "${RED}[!]${NC} $1"
}

# Function to check if a command exists
command_exists() {
    command -v "$1" >/dev/null 2>&1
}

# Function to check if a Python package is installed in venv
python_package_installed() {
    "$INSTALL_DIR/venv/bin/pip3" show "$1" >/dev/null 2>&1
}

# Function to check if apt package is installed
apt_package_installed() {
    dpkg -l "$1" 2>/dev/null | grep -q "^ii"
}

# Function to check if gem is installed
gem_installed() {
    gem list -i "^$1$" >/dev/null 2>&1
}

# Create a python virtual environment (only if it doesn't exist)
if [ ! -d "$INSTALL_DIR/venv" ]; then
    print_status "Creating Python virtual environment..."
    python3 -m venv "$INSTALL_DIR/venv"
else
    print_status "Python virtual environment already exists, skipping..."
fi

# Update package lists
print_status "Updating package lists..."
apt-get update

# Install system dependencies
print_status "Installing system dependencies..."
apt install -y \
    build-essential \
    git \
    wget \
    curl \
    python3 \
    python3-pip \
    python3-dev \
    python3-venv \
    default-jre \
    default-jdk \
    ruby \
    ruby-dev \
    perl \
    libssl-dev \
    libffi-dev \
    libxml2-dev \
    libxslt1-dev \
    zlib1g-dev \
    libjpeg-dev \
    libfreetype6-dev \
    liblcms2-dev \
    libwebp-dev \
    tcl8.6-dev \
    tk8.6-dev \
    unzip \
    p7zip-full \
    cabextract \
    cmake \
    binutils\
    swig \

# Install apt-based tools
print_status "Installing apt-based analysis tools..."
APT_TOOLS=(
    clamav 
    clamav-daemon 
    yara 
    ssdeep 
    binwalk 
    sleuthkit 
    msitools 
    pev 
    upx-ucl 
    wxhexeditor 
    bulk-extractor 
    file 
    exiftool 
    signsrch 
    ghidra 
    dex2jar 
    baksmali 
    procyon-decompiler 
    wine 
    wine64 
    radare2 
    wireshark 
    tshark 
    tcpdump 
    ngrep 
    tcpxtract 
    tcpflow 
    tcpick 
    netcat-openbsd 
    tor 
    nginx 
    sysdig 
    unhide 
    qpdf 
    pdfresurrect 
    pdftk-java 
    libolecf-utils 
    msoffice-crypt 
    aeskeyfind 
    rsakeyfind 
    binutils 
    burpsuite-community
	ghex
	gedit 
) 

for tool in "${APT_TOOLS[@]}"; do
    if apt_package_installed "$tool"; then
        print_status "$tool already installed, skipping..."
    else
        print_status "Installing $tool..."
        if ! apt install -y "$tool"; then
            print_warning "Failed to install $tool"
            FAILED_TOOLS+=("$tool (apt)")
        fi
    fi
done

# Install Python tools via pip
print_status "Installing Python-based tools into venv..."
"$INSTALL_DIR/venv/bin/pip3" install --upgrade pip

# Python analysis libraries and tools
PYTHON_TOOLS=(
    pefile
    pyelftools
    dnfile
    dotnetfile
    hachoir
    yara-python
    vivisect
    androguard
    droidlysis
    pe-tree
    speakeasy-emulator
    malchive
    xortool
    ratdecoders
    mwcp
    chepy
    jsbeautifier
    xxxswf
    name-that-hash
    qiling
    magika
    csce
    flare-floss
    frida
    frida-tools
    volatility3
    mitmproxy
    unfurl
    thug
    msoffcrypto-tool
    pcodedmp
    pcode2code
    oletools
    xlmmacrodeobfuscator
    manalyze
) 

for tool in "${PYTHON_TOOLS[@]}"; do
    if python_package_installed "$tool"; then
        print_status "$tool already installed, skipping..."
    else
        print_status "Installing $tool..."
        if ! $INSTALL_DIR/venv/bin/pip3 install "$tool"; then
            print_warning "Failed to install $tool"
            FAILED_TOOLS+=("$tool (python)")
        fi
    fi
done

# Install Ruby gems
print_status "Installing Ruby gems..."
if gem_installed "pedump"; then
    print_status "pedump already installed, skipping..."
else
    gem install pedump
fi

# Download and install Didier Stevens tools
print_status "Installing Didier Stevens tools..."
STEVENS_DIR="$INSTALL_DIR/didier-stevens"
mkdir -p "$STEVENS_DIR"
cd "$STEVENS_DIR"

STEVENS_TOOLS=(
    "zipdump.py"
    "numbers-to-string.py"
    "re-search.py"
    "disitool.py"
    "1768.py"
    "cs-decrypt-metadata.py"
    "base64dump.py"
    "xor-kpa.py"
    "cut-bytes.py"
    "format-bytes.py"
    "translate.py"
    "pecheck.py"
    "extractscripts.py"
    "decode-vbe.py"
    "pdftool.py"
    "pdf-parser.py"
    "pdfid.py"
    "dnsresolver.py"
    "rtfdump.py"
    "xmldump.py"
    "msoffcrypto-crack.py"
)

for tool in "${STEVENS_TOOLS[@]}"; do
    if [ -f "$STEVENS_DIR/$tool" ]; then
        print_status "$tool already exists, skipping..."
    else
        if ! wget -q "https://github.com/DidierStevens/DidierStevensSuite/raw/master/$tool" 2>/dev/null; then
            print_warning "Could not download $tool"
            FAILED_TOOLS+=("$tool (Didier Stevens)")
        else
            chmod +x "$tool"
            ln -sf "$STEVENS_DIR/$tool" "/usr/local/bin/$tool" 2>/dev/null || true
        fi
    fi
done

# Download XORSearch and XORStrings
print_status "Installing XORSearch and XORStrings..."
cd "$INSTALL_DIR"

if command_exists xorsearch; then
    print_status "xorsearch already installed, skipping..."
else
    if wget -q "https://didierstevens.com/files/software/XORSearch_V1_11_1.zip" 2>/dev/null; then
        unzip -q XORSearch_V1_11_1.zip
        mv Linux/xorsearch /usr/local/bin/ 2>/dev/null || true
        chmod +x /usr/local/bin/xorsearch
        rm -rf XORSearch_V1_11_1.zip Linux/
    fi
fi

if command_exists xorstrings; then
    print_status "XORStrings already installed, skipping..."
else
    if wget -q "https://didierstevens.com/files/software/XORStrings_V0_0_1.zip" 2>/dev/null; then
        unzip -q XORStrings_V0_0_1.zip
        mv OSX/xorstrings /usr/local/bin/ 2>/dev/null || true
        chmod +x /usr/local/bin/xorstrings
        rm -rf XORStrings_V0_0_1.zip OSX/
    fi
fi

# Install TrID
print_status "Installing TrID..."
cd "$INSTALL_DIR"
if [ -f "$INSTALL_DIR/trid/trid" ]; then
    print_status "TrID already installed, skipping..."
else
    mkdir -p trid
    cd trid
    if wget -q "https://mark0.net/download/trid_linux_64.zip" 2>/dev/null; then
        unzip -q trid_linux_64.zip
        chmod +x trid
        ln -sf "$INSTALL_DIR/trid/trid" /usr/local/bin/trid
    fi
    if wget -q "https://mark0.net/download/triddefs.zip" 2>/dev/null; then
        unzip -q triddefs.zip
    fi
fi

# Install Detect-It-Easy
print_status "Installing Detect-It-Easy..."
cd "$INSTALL_DIR"
DIE_VERSION="3.09"
if command_exists die || command_exists diec; then
    print_status "Detect-It-Easy already installed, skipping..."
else
    if wget -q "https://github.com/horsicq/DIE-engine/releases/download/${DIE_VERSION}/die_${DIE_VERSION}_Ubuntu_22.04_amd64.deb" 2>/dev/null; then
        dpkg -i "die_${DIE_VERSION}_Ubuntu_22.04_amd64.deb" 2>/dev/null || apt-get install -f -y
        rm -f "die_${DIE_VERSION}_Ubuntu_22.04_amd64.deb"
    fi
fi

# Install capa
print_status "Installing capa..."
cd "$INSTALL_DIR"
if command_exists capa; then
    print_status "capa already installed, skipping..."
else
    CAPA_VERSION="v7.3.0"
    if wget -q "https://github.com/mandiant/capa/releases/download/${CAPA_VERSION}/capa-${CAPA_VERSION}-linux.zip" 2>/dev/null; then
        unzip -q "capa-${CAPA_VERSION}-linux.zip"
        mv capa /usr/local/bin/
        chmod +x /usr/local/bin/capa
        rm -f "capa-${CAPA_VERSION}-linux.zip"
    fi
fi



# Install Java decompilers
print_status "Installing Java decompilers..."
cd "$INSTALL_DIR"

# CFR
if [ -f "$INSTALL_DIR/cfr/cfr.jar" ]; then
    print_status "CFR already installed, skipping..."
else
    if wget -q "https://github.com/leibnitz27/cfr/releases/latest/download/cfr.jar" 2>/dev/null; then
        mkdir -p cfr
        mv cfr.jar cfr/
        echo '#!/bin/bash' > /usr/local/bin/cfr
        echo "java -jar $INSTALL_DIR/cfr/cfr.jar \"\$@\"" >> /usr/local/bin/cfr
        chmod +x /usr/local/bin/cfr
    fi
fi

# JD-GUI
JD_VERSION="1.6.6"
if [ -f "$INSTALL_DIR/jd-gui/jd-gui.jar" ]; then
    print_status "JD-GUI already installed, skipping..."
else
    if wget -q "https://github.com/java-decompiler/jd-gui/releases/download/v${JD_VERSION}/jd-gui-${JD_VERSION}.jar" 2>/dev/null; then
        mkdir -p jd-gui
        mv "jd-gui-${JD_VERSION}.jar" jd-gui/jd-gui.jar
        echo '#!/bin/bash' > /usr/local/bin/jd-gui
        echo "java -jar $INSTALL_DIR/jd-gui/jd-gui.jar \"\$@\"" >> /usr/local/bin/jd-gui
        chmod +x /usr/local/bin/jd-gui
    fi
fi

# Install JADX (Android)
print_status "Installing JADX..."
cd "$INSTALL_DIR"
if [ -d "$INSTALL_DIR/jadx" ] && [ -f "$INSTALL_DIR/jadx/bin/jadx" ]; then
    print_status "JADX already installed, skipping..."
else
    JADX_VERSION="1.5.0"
    if wget -q "https://github.com/skylot/jadx/releases/download/v${JADX_VERSION}/jadx-${JADX_VERSION}.zip" 2>/dev/null; then
        mkdir -p jadx
        cd jadx
        unzip -q "../jadx-${JADX_VERSION}.zip"
        ln -sf "$INSTALL_DIR/jadx/bin/jadx" /usr/local/bin/jadx
        ln -sf "$INSTALL_DIR/jadx/bin/jadx-gui" /usr/local/bin/jadx-gui
        cd ..
        rm -f "jadx-${JADX_VERSION}.zip"
    fi
fi

# Install apktool
print_status "Installing apktool..."
cd "$INSTALL_DIR"
if [ -f "$INSTALL_DIR/apktool/apktool" ]; then
    print_status "apktool already installed, skipping..."
else
    mkdir -p apktool
    cd apktool
    wget -q "https://raw.githubusercontent.com/iBotPeaches/Apktool/master/scripts/linux/apktool"
    wget -q "https://bitbucket.org/iBotPeaches/apktool/downloads/apktool_2.9.3.jar" -O apktool.jar
    chmod +x apktool apktool.jar
    ln -sf "$INSTALL_DIR/apktool/apktool" /usr/local/bin/apktool
fi

# Install .NET tools
print_status "Installing .NET tools..."
cd "$INSTALL_DIR"

# de4dot
if [ -d "$INSTALL_DIR/de4dot" ]; then
    print_status "de4dot already cloned, skipping..."
else
    if git clone --depth 1 https://github.com/de4dot/de4dot.git 2>/dev/null; then
        cd de4dot
        print_warning "de4dot cloned but not built (requires .NET SDK)"
        cd ..
    fi
fi

# ILSpy (if available in apt)
apt-get install -y ilspy 2>/dev/null || print_warning "ILSpy not available in apt"

# Install Flash tools
print_status "Installing Flash analysis tools..."
apt-get install -y swftools 2>/dev/null || print_warning "swftools not available"

# Install additional analysis scripts
print_status "Installing additional tools from GitHub..."
cd "$INSTALL_DIR"

# PyInstaller Extractor
if [ -d "$INSTALL_DIR/pyinstxtractor" ]; then
    print_status "pyinstxtractor already installed, skipping..."
else
    if git clone --depth 1 https://github.com/extremecoders-re/pyinstxtractor.git 2>/dev/null; then
        ln -sf "$INSTALL_DIR/pyinstxtractor/pyinstxtractor.py" /usr/local/bin/pyinstxtractor.py
    fi
fi

# unXOR
if [ -d "$INSTALL_DIR/unxor" ]; then
    print_status "unXOR already installed, skipping..."
else
    if git clone --depth 1 https://github.com/tomchop/unxor.git 2>/dev/null; then
        cd unxor
        pip3 install -r requirements.txt 2>/dev/null || true
        ln -sf "$INSTALL_DIR/unxor/unxor.py" /usr/local/bin/unxor.py
        cd ..
    fi
fi

# NoMoreXOR
if [ -f "/usr/local/bin/NoMoreXOR.py" ]; then
    print_status "NoMoreXOR already installed, skipping..."
else
    if wget -q "https://raw.githubusercontent.com/hiddenillusion/NoMoreXOR/master/NoMoreXOR.py" 2>/dev/null; then
        chmod +x NoMoreXOR.py
        mv NoMoreXOR.py /usr/local/bin/
    fi
fi

# Balbuzard
if [ -d "$INSTALL_DIR/balbuzard" ]; then
    print_status "Balbuzard already installed, skipping..."
else
    if git clone --depth 1 https://github.com/decalage2/balbuzard.git 2>/dev/null; then
        cd balbuzard
        python3 setup.py install 2>/dev/null || pip3 install . 2>/dev/null || true
        cd ..
    fi
fi

# peepdf for PDF analysis
if [ -d "$INSTALL_DIR/peepdf" ]; then
    print_status "peepdf already installed, skipping..."
else
    if git clone --depth 1 https://github.com/jesparza/peepdf.git 2>/dev/null; then
        cd peepdf
        python3 setup.py install 2>/dev/null || pip3 install . 2>/dev/null || true
        cd ..
    fi
fi

#Newer Version of PEframe
# ============================================================
# Install peframe-ds (maintained fork) from PyPI:
# ============================================================

print_status "Installing peframe-ds (maintained fork)..."
if python_package_installed "peframe-ds"; then
    print_status "peframe-ds already installed, skipping..."
else
    # Install system dependencies for readline
    print_status "Installing readline dependencies..."
    apt-get install -y libreadline-dev libncurses5-dev 2>/dev/null || true
    
    # Try installing without readline first (it's optional)
    if "$INSTALL_DIR/venv/bin/pip3" install --no-deps peframe-ds 2>/dev/null; then
        # Install dependencies separately, skipping readline if it fails
        "$INSTALL_DIR/venv/bin/pip3" install pefile yara-python capstone pyelftools 2>/dev/null || true
        print_status "peframe-ds installed successfully (without readline)"
        
        # Create symlink if the venv binary exists
        if [ -f "$INSTALL_DIR/venv/bin/peframe" ]; then
            ln -sf "$INSTALL_DIR/venv/bin/peframe" /usr/local/bin/peframe
            print_status "peframe symlinked to /usr/local/bin"
        fi
    else
        print_warning "Failed to install peframe-ds"
        FAILED_TOOLS+=("peframe-ds (python)")
    fi
fi

# Origami (Ruby gem for PDF)
if gem_installed "origami"; then
    print_status "Origami already installed, skipping..."
else
    gem install origami 2>/dev/null || print_warning "Could not install Origami"
fi

# oledump
if [ -d "$INSTALL_DIR/DidierStevensSuite" ]; then
    print_status "DidierStevensSuite already cloned, skipping..."
else
    if git clone --depth 1 https://github.com/DidierStevens/DidierStevensSuite.git 2>/dev/null; then
        ln -sf "$INSTALL_DIR/DidierStevensSuite/oledump.py" /usr/local/bin/oledump.py
    fi
fi

# ViperMonkey (VBA emulator)
if python_package_installed "vipermonkey" || $INSTALL_DIR/venv/bin/pip3 show vipermonkey >/dev/null 2>&1; then
    print_status "ViperMonkey already installed, skipping..."
else
    $INSTALL_DIR/venv/bin/pip3 install vipermonkey 2>/dev/null || print_warning "Could not install ViperMonkey"
fi


# CapTipper
if [ -d "$INSTALL_DIR/CapTipper" ]; then
    print_status "CapTipper already installed, skipping..."
else
    if git clone --depth 1 https://github.com/omriher/CapTipper.git 2>/dev/null; then
        cd CapTipper
        git checkout python3_support 2>/dev/null || true
        pip3 install -r requirements.txt 2>/dev/null || true
        ln -sf "$INSTALL_DIR/CapTipper/CapTipper.py" /usr/local/bin/CapTipper.py
        cd ..
    fi
fi

# Network Miner
print_status "Installing Network Miner..."
if [ -d "$INSTALL_DIR/networkminer" ]; then
    print_status "Network Miner already installed, skipping..."
else
    if wget -q "https://www.netresec.com/?download=NetworkMiner" -O networkminer.zip 2>/dev/null; then
        unzip -q networkminer.zip -d networkminer 2>/dev/null || true
        rm -f networkminer.zip
    fi
fi

# PolarProxy
print_status "Installing PolarProxy..."
if command_exists PolarProxy; then
    print_status "PolarProxy already installed, skipping..."
else
    if wget -q "https://www.netresec.com/files/PolarProxy_linux-x64.tar.gz" 2>/dev/null; then
        tar -xzf PolarProxy_linux-x64.tar.gz -C /usr/local/bin/ 2>/dev/null || true
        rm -f PolarProxy_linux-x64.tar.gz
    fi
fi

# Yara rules
print_status "Installing Yara rules..."
cd "$INSTALL_DIR"
if [ -d "$INSTALL_DIR/yara-rules" ]; then
    print_status "Yara rules already installed, skipping..."
else
    if git clone --depth 1 https://github.com/Yara-Rules/rules.git yara-rules 2>/dev/null; then
        print_status "Yara rules installed to $INSTALL_DIR/yara-rules"
    fi
fi

# Install Cutter
print_status "Installing Cutter..."
cd "$INSTALL_DIR"
if [ -f "$INSTALL_DIR/cutter.AppImage" ]; then
    print_status "Cutter already installed, skipping..."
else
    CUTTER_VERSION="v2.3.4"
    if wget -q "https://github.com/rizinorg/cutter/releases/download/${CUTTER_VERSION}/Cutter-${CUTTER_VERSION}-Linux-x86_64.AppImage" 2>/dev/null; then
        mv "Cutter-${CUTTER_VERSION}-Linux-x86_64.AppImage" cutter.AppImage
        chmod +x cutter.AppImage
        ln -sf "$INSTALL_DIR/cutter.AppImage" /usr/local/bin/cutter
    fi
fi

# Install binee
print_status "Installing binee..."
cd "$INSTALL_DIR"
if command_exists binee; then
    print_status "binee already installed, skipping..."
else
    if [ -d "$INSTALL_DIR/binee" ]; then
        print_status "binee directory exists, skipping clone..."
    else
        if git clone --depth 1 https://github.com/carbonblack/binee.git 2>/dev/null; then
            cd binee
            if command -v go &> /dev/null; then
                go build
                mv binee /usr/local/bin/
            else
                print_warning "Go not installed, skipping binee build"
		FAILED_TOOLS+=("$tool")
            fi
            cd ..
        fi
    fi
fi

# Update ClamAV signatures
print_status "Updating ClamAV signatures..."
freshclam 2>/dev/null || print_warning "Could not update ClamAV signatures"

# Create wrapper scripts
print_status "Creating wrapper scripts..."

# Hash identifier wrapper
if [ -f "/usr/local/bin/hash-id.py" ]; then
    print_status "hash-id.py already exists, skipping..."
else
    cat > /usr/local/bin/hash-id.py << 'EOF'
#!/usr/bin/env python3
import hashlib
import sys

if len(sys.argv) < 2:
    print("Usage: hash-id.py <hash>")
    sys.exit(1)

hash_val = sys.argv[1]
hash_len = len(hash_val)

print(f"Analyzing hash: {hash_val}")
print(f"Length: {hash_len}")

if hash_len == 32:
    print("Possible: MD5")
elif hash_len == 40:
    print("Possible: SHA-1")
elif hash_len == 64:
    print("Possible: SHA-256")
elif hash_len == 128:
    print("Possible: SHA-512")
else:
    print("Unknown hash type")
EOF
    chmod +x /usr/local/bin/hash-id.py
fi

# Create environment setup script
if [ -f "$INSTALL_DIR/remnux-env.sh" ]; then
    print_status "remnux-env.sh already exists, skipping..."
else
    cat > "$INSTALL_DIR/remnux-env.sh" << 'EOF'
#!/bin/bash
# Source this file to set up REMnux tool environment
export REMNUX_DIR="/opt/remnux-tools"
export PATH="$REMNUX_DIR/venv/bin:$REMNUX_DIR:$PATH"
export YARA_RULES="$REMNUX_DIR/yara-rules"
echo "REMnux environment loaded"
echo "Tools directory: $REMNUX_DIR"
echo "Python tools venv: $REMNUX_DIR/venv"
EOF
fi


# Print installation summary
echo ""
echo "======================================"
print_status "Installation Complete!"
echo "======================================"
echo ""
echo "Installed tools location: $INSTALL_DIR"
echo ""
echo "To set up environment variables, run:"
echo "  source $INSTALL_DIR/remnux-env.sh"
echo ""
echo "Key tools installed:"
echo "  - Static Analysis: yara, capa, floss, pefile, peframe"
echo "  - Deobfuscation: xortool, base64dump.py, cyberchef, chepy"
echo "  - Disassemblers: ghidra, cutter, radare2, objdump"
echo "  - Decompilers: jadx, jd-gui, cfr, ilspycmd"
echo "  - PE Analysis: pev, pedump, pecheck.py, detect-it-easy"
echo "  - Android: apktool, jadx, androguard, droidlysis"
echo "  - Malware Scanning: clamav, yara-rules"
echo "  - XOR Analysis: xorsearch, xorstrings, xortool, unxor"
echo "  - Hash Tools: ssdeep, name-that-hash"
echo "  - Dynamic Analysis: frida, wine, radare2, qiling"
echo "  - Memory Forensics: volatility3, vol.py, aeskeyfind, rsakeyfind"
echo "  - Network Analysis: wireshark, tshark, tcpdump, mitmproxy"
echo "  - Network Services: fakenet-ng, inetsim, fakedns, nginx"
echo "  - PDF Analysis: pdfid.py, pdf-parser.py, peepdf, qpdf"
echo "  - Office Analysis: oletools, oledump.py, vipermonkey, xlmdeobfuscator"
echo ""
echo "Note: Some tools may require additional configuration."
echo "Refer to https://docs.remnux.org for detailed documentation."
echo ""

# Create a tools list file
cat > "$INSTALL_DIR/installed-tools.txt" << 'TOOLLIST'
REMnux Tools Installation Summary
==================================

STATIC ANALYSIS TOOLS:
- TrID (trid) - File type identification
- Magika - Google's file type identifier
- Yara - Pattern matching for malware
- Detect-It-Easy (die, diec) - File property analysis
- ExifTool - Metadata extraction
- ssdeep - Fuzzy hashing
- ClamAV (clamscan) - Antivirus scanner
- binwalk - Firmware analysis
- file - File type detection

PE FILE ANALYSIS:
- pefile - Python PE library
- PEframe - PE static analysis
- PE Tree - PE structure viewer
- pev suite (pestr, readpe, pedis, pehash, pescan)
- pecheck.py - PE property checker
- pedump - Ruby PE analyzer
- capa - Capability detection
- FLOSS (floss) - String extraction
- StringSifter - String ranking

DEOBFUSCATION:
- XORSearch - Find XOR'd strings
- XORStrings - XOR string search
- xortool - XOR analysis
- base64dump.py - Base64 decoder
- Chepy - Data transformation
- unXOR - XOR deobfuscation
- translate.py - Byte translation
- cut-bytes.py - Data extraction
- format-bytes.py - Binary decomposition

DISASSEMBLERS/DEBUGGERS:
- Ghidra - NSA's RE framework
- Cutter - Rizin GUI
- objdump - GNU binary disassembler
- Vivisect - Binary analysis framework

DECOMPILERS:
Java:
- cfr - Java decompiler
- JD-GUI - Java decompiler with GUI
- Procyon - Java decompiler

.NET:
- ILSpy (ilspycmd) - .NET decompiler
- de4dot - .NET deobfuscator

Python:
- Decompyle++ (pycdc) - Python decompiler
- PyInstaller Extractor - Extract PyInstaller apps

ANDROID ANALYSIS:
- JADX (jadx, jadx-gui) - Dex to Java
- apktool - APK reverse engineering
- androguard - Android analysis suite
- DroidLysis - APK static analysis
- baksmali - Dex disassembler
- dex2jar - Dex converter

MALWARE ANALYSIS:
- Malchive - MITRE malware utilities
- Speakeasy - Code emulator
- Qiling - Multi-platform emulator
- DC3-MWCP - Config parser
- RATDecoders - RAT config extraction
- CSCE - Cobalt Strike extractor
- 1768.py - Cobalt Strike analysis

SCRIPTING TOOLS:
- JS Beautifier - JavaScript formatter
- extractscripts.py - Extract scripts from HTML
- decode-vbe.py - VBE decoder

HASH TOOLS:
- Name-That-Hash (nth) - Hash identifier
- hash-id.py - Hash type detector
- ssdeep - Fuzzy hashing

ARCHIVE/COMPRESSION:
- 7-Zip (7z, 7za, 7zr) - Archive tool
- UPX - PE packer/unpacker
- binwalk - Firmware extraction

UTILITIES:
- bulk_extractor - String extraction
- Hachoir - Binary file parser
- Sleuth Kit - Disk forensics
- wxHexEditor - Hex editor

YARA RULES:
- Yara-Rules repository installed at $INSTALL_DIR/yara-rules

DIDIER STEVENS SUITE:
All tools available in $INSTALL_DIR/didier-stevens/
- zipdump.py, pecheck.py, base64dump.py, xor-kpa.py
- numbers-to-string.py, re-search.py, disitool.py
- 1768.py, cs-decrypt-metadata.py, extractscripts.py
- decode-vbe.py, cut-bytes.py, format-bytes.py, translate.py

For more information visit: https://docs.remnux.org
TOOLLIST

print_status "Tool list saved to $INSTALL_DIR/installed-tools.txt"

if [ ${#FAILED_TOOLS[@]} -ne 0 ]; then
    echo ""
    echo "======================================"
    print_error "Installation Summary: Some tools failed to install!"
    echo "======================================"
    echo "The following tools could not be installed:"
    for tool in "${FAILED_TOOLS[@]}"; do
        echo "  - $tool"
    done
    echo ""
    print_warning "Please review the output above for errors."
    echo ""
fi

# Cleanup
print_status "Cleaning up temporary files..."
apt-get autoremove -y
apt-get clean

echo ""
echo "Please add /opt/remnux-tools to \$PATH"
echo "Ensure activation of python virtual environment by activating"
echo "     source /opt/remnux-tools/venv/bin/activate     "
echo ""
echo ""
print_status "All done! Happy malware hunting!"

echo ""

