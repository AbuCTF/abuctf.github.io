#!/bin/bash

set -e

echo "[*] Creating folder structure..."
mkdir -p content/docs/CTF/2025
mkdir -p content/docs/CTF/2024
mkdir -p content/docs/Research
mkdir -p content/docs/Dev

echo "[*] Moving CTF 2025 challenges..."
mv content/docs/NahamConCTF2025 content/docs/CTF/2025/
mv content/docs/UMassCTF content/docs/CTF/2025/
mv content/docs/WolvCTF2025 content/docs/CTF/2025/
mv content/docs/ApoorvCTF content/docs/CTF/2025/
mv content/docs/KashiCTF content/docs/CTF/2025/
mv content/docs/InfoSecCTF content/docs/CTF/2025/
mv content/docs/IrisCTF2025 content/docs/CTF/2025/

echo "[*] Moving CTF 2024 challenges..."
mv content/docs/corCTF content/docs/CTF/2024/
mv content/docs/DownUnderCTF content/docs/CTF/2024/
mv content/docs/H7CTFChallenges content/docs/CTF/2024/
mv content/docs/HackHavocCTF content/docs/CTF/2024/
mv content/docs/JuniorCryptCTF content/docs/CTF/2024/
mv content/docs/LITCTF content/docs/CTF/2024/
mv content/docs/n00bzCTF content/docs/CTF/2024/
mv content/docs/NiteCTF2024 content/docs/CTF/2024/
mv content/docs/OSCTF content/docs/CTF/2024/
mv content/docs/RVCECTF content/docs/CTF/2024/

echo "[*] Moving CTF Inventory..."
mv content/docs/CTFInventory content/docs/CTF/

echo "[*] Moving Research and Dev..."
mv content/docs/Pwnology content/docs/Research/
mv content/docs/XXEVuln content/docs/Research/
mv content/docs/PrivilegeEscalation content/docs/Research/
mv content/docs/PreSecurity content/docs/Research/
mv content/docs/JrPenTester content/docs/Research/
mv content/docs/Web3 content/docs/Research/
mv content/docs/H7CTFInfra content/docs/Dev/

echo "[*] Creating _index.md files..."

# CTF Root
cat > content/docs/CTF/_index.md <<EOF
+++
title = "CTF"
weight = 1
+++
EOF

# CTF 2025
cat > content/docs/CTF/2025/_index.md <<EOF
+++
title = "2025"
weight = 1
+++
EOF

# CTF 2024
cat > content/docs/CTF/2024/_index.md <<EOF
+++
title = "2024"
weight = 2
+++
EOF

# Research
cat > content/docs/Research/_index.md <<EOF
+++
title = "Research"
weight = 2
+++
EOF

# Dev
cat > content/docs/Dev/_index.md <<EOF
+++
title = "Dev"
weight = 3
+++
EOF

echo "[*] Done! Menu structure is reorganized."
