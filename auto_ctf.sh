#!/bin/bash

# Function for Nmap scan
echo "    ___            __                  ______  ______    ______"
echo "   /   |  __  __  / /_  ____          / ____/ /_  __/   / ____/"
echo "  / /| | / / / / / __/ / __ \ ______ / /       / /     / /_    "
echo " / ___ |/ /_/ / / /_  / /_/ //_____// /___    / /     / __/    "
echo "/_/  |_|\__,_/  \__/  \____/        \____/   /_/     /_/       "
echo
echo "Created by: Bryce Kimber"
echo
nmap_scan() {
    read -p "Enter the target IP or hostname: " target

    # Display options for Nmap scan types
    echo "Nmap Scan Types:"
    echo "1. Quick Scan (Top 100 Ports) - Performs a scan of the top 100 ports. (Flags: -T4 -F)"
    echo "2. Full Scan - Performs a comprehensive scan of all 65535 ports. (Flags: -p-)"
    echo "3. Intense Scan - Performs a more aggressive scan with host discovery, service version detection, and OS detection. (Flags: -T4 -A)"
    echo "4. Custom Scan - Allows you to enter custom Nmap options."
    echo
    read -p "Enter the number corresponding to the desired scan type: " scan_option

    case $scan_option in
        1)
            echo "Scanning $target with Quick Scan (Top 100 Ports)..."
            nmap -Pn -T4 -F "$target"
            ;;
        2)
            echo "Scanning $target with Full Scan..."
            nmap -Pn -p- "$target"
            ;;
        3)
            echo "Scanning $target with Intense Scan..."
            nmap -Pn -T4 -A "$target"
            ;;
        4)
            echo "Custom Scan Options:"
            echo "-sS: Stealthy SYN scan"
            echo "-sT: TCP connect scan"
            echo "-sU: UDP scan"
            echo "-sV: Version detection"
            echo "-A: Aggressive scan (includes OS detection, version detection, script scanning, and traceroute)"
            echo "-F: Fast scan mode (scan fewer ports)"
            echo "-p: Scan specific ports (e.g., -p 22,80,443)"
            echo "-Pn: Treat all hosts as online -- skip host discovery and bypass ping blockers"
            read -p "Enter custom Nmap options: " custom_options
            echo "Scanning $target with Custom Options: $custom_options"
            nmap $custom_options "$target"
            ;;
        *)
            echo "Invalid option. Please try again."
            ;;
    esac
}

# Function for Dirb scan
dirb_scan() {
    read -p "Enter the target URL: " target_url
    read -p "Enter the wordlist file path: " wordlist
    echo "Running dirb on $target_url using wordlist: $wordlist"
    dirb "$target_url" "$wordlist"
}

# Function for Stegseek extraction
stegseek_extract() {
    read -p "Enter the path to the image file: " image_path
    read -p "Enter the path to the wordlist file: " wordlist_path
    stegseek -sf "$image_path" -wl "$wordlist_path"
}

# Function for smb enumeration
smb_enum() {
    read -p "Enter the target IP: " smb_target

    # Enumerate SMB server using Nmap scripts
    echo "Enumerating SMB server using Nmap scripts..."
    nmap -v -p139,445 --script=smb-double-pulsar-backdoor.nse,smb-enum-domains.nse,smb-enum-groups.nse,smb-enum-processes.nse,smb-enum-services.nse,smb-enum-sessions.nse,smb-enum-shares.nse,smb-enum-users.nse,smb-flood.nse,smb-ls.nse,smb-mbenum.nse,smb-os-discovery.nse,smb-print-text.nse,smb-protocols.nse,smb-psexec.nse,smb-security-mode.nse,smb-server-stats.nse,smb-system-info.nse,smb-vuln-conficker.nse,smb-vuln-cve2009-3103.nse,smb-vuln-cve-2017-7494.nse,smb-vuln-ms06-025.nse,smb-vuln-ms07-029.nse,smb-vuln-ms08-067.nse,smb-vuln-ms10-054.nse,smb-vuln-ms10-061.nse,smb-vuln-ms17-010.nse,smb-vuln-regsvc-dos.nse,smb-vuln-webexec.nse,smb-webexec-exploit.nse "$smb_target"

    # Enumerate SMB shares using enum4linux
    echo "Enumerating SMB shares using enum4linux..."
    enum4linux -a "$smb_target"
}

# Function for ftp enumeration
ftp_enum() {
    read -p "Enter the target IP: " ftp_target

    # Enumerate FTP server using specific Nmap options
    echo "Enumerating FTP server using Nmap..."
    nmap -Pn -sV -p21 -sC -A "$ftp_target"
}

# Function for SSH enumeration
ssh_enum() {
    read -p "Enter the target IP: " ssh_target

    # Enumerate SSH server using nmap with default SSH scripts
    echo "Enumerating SSH server using Nmap scripts..."
    nmap -Pn -p 22 -sC "$ssh_target"

}

# Main menu
while true; do
    echo "===== Main Menu ====="
    echo "1. Nmap Scan"
    echo "2. Dirb Scan"
    echo "3. Enumeration"
    echo "4. Stegseek"
    echo "5. Exit"
    echo "====================="

    read -p "Enter your choice: " choice

    case $choice in
        1)
            nmap_scan
            ;;
        2)
            dirb_scan
            ;;
        3)
            # Enumeration submenu
            while true; do
                echo "===== Enumeration Menu ====="
                echo "1. SMB Enumeration"
                echo "2. FTP Enumeration"
                echo "3. SSH Enumeration"
                echo "4. Back to Main Menu"
                echo "==========================="

                read -p "Enter your choice: " enum_choice

                case $enum_choice in
                    1)
                        smb_enum
                        ;;
                    2)
                        ftp_enum
                        ;;
                    3)
                        ssh_enum
                        ;;
                    4)
                        break # Go back to the main menu
                        ;;
                    *)
                        echo "Invalid choice. Please try again."
                        ;;
                esac
            done
            ;;

        4)
            stegseek_extract
            ;;
        5)
            echo "Exiting. Goodbye!"
            exit 0
            ;;
        *)
            echo "Invalid choice. Please try again."
            ;;
    esac

    read -p "Press Enter to continue..."
done