import subprocess
import os

try:
    import paramiko
    HAS_PARAMIKO = True
except ImportError:
    HAS_PARAMIKO = False

def scan_system_config(target_ip: str, username: str = None, password: str = None, ssh_key: str = None) -> dict:
    """
    Automates system scans for configurations and packages.
    Connects locally if target_ip is 127.0.0.1 or localhost, 
    otherwise attempts remote connection via SSH using Paramiko.
    """
    results = {
        "status": "success",
        "target": target_ip,
        "os_info": "",
        "vulnerable_configs": [],
        "installed_packages_count": 0,
        "errors": []
    }
    
    is_local = target_ip in ["127.0.0.1", "localhost", "::1"]

    if is_local:
        return _run_local_scan(results)
    else:
        if not HAS_PARAMIKO:
            results["status"] = "failed"
            results["errors"].append("Paramiko library not installed. Cannot run remote config scans over SSH.")
            return results
        return _run_remote_scan(target_ip, username, password, ssh_key, results)


def _run_local_scan(results: dict) -> dict:
    """Runs config and package checks using local OS subprocesses."""
    try:
        # 1. OS Info
        if os.name == "posix":
            uname = subprocess.run(["uname", "-a"], capture_output=True, text=True)
            results["os_info"] = uname.stdout.strip()
        elif os.name == "nt":
            win_ver = subprocess.run(["cmd", "/c", "ver"], capture_output=True, text=True)
            results["os_info"] = win_ver.stdout.strip()

        # 2. Config Scanning (SSH)
        if os.path.exists("/etc/ssh/sshd_config"):
            try:
                with open("/etc/ssh/sshd_config", "r") as f:
                    content = f.read()
                    if "PermitRootLogin yes" in content:
                        results["vulnerable_configs"].append("SSH allows root login (PermitRootLogin yes)")
                    if "PasswordAuthentication yes" in content:
                        results["vulnerable_configs"].append("SSH allows password authentication (PasswordAuthentication yes)")
            except PermissionError:
                results["errors"].append("Permission denied reading /etc/ssh/sshd_config locally.")

        # 3. Package Scanning
        if os.path.exists("/usr/bin/dpkg"):
            dpkg = subprocess.run(["dpkg", "-l"], capture_output=True, text=True)
            results["installed_packages_count"] = len(dpkg.stdout.split('\n')) - 5 # approx lines excluding header
        elif os.path.exists("/usr/bin/rpm"):
            rpm = subprocess.run(["rpm", "-qa"], capture_output=True, text=True)
            results["installed_packages_count"] = len(rpm.stdout.split('\n'))
            
    except Exception as e:
        results["errors"].append(f"Local scan encountered an error: {str(e)}")
        
    return results


def _run_remote_scan(target_ip: str, username: str, password: str, ssh_key: str, results: dict) -> dict:
    """Connects via SSH to perform config and package auditing."""
    if not username:
        results["status"] = "failed"
        results["errors"].append("Username required for remote scan.")
        return results

    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    
    try:
        if ssh_key:
            client.connect(target_ip, username=username, key_filename=ssh_key, timeout=10)
        else:
            client.connect(target_ip, username=username, password=password, timeout=10)
            
        # 1. OS Info
        stdin, stdout, stderr = client.exec_command("uname -a")
        results["os_info"] = stdout.read().decode('utf-8').strip()
        
        # 2. Config Scanning
        stdin, stdout, stderr = client.exec_command("cat /etc/ssh/sshd_config")
        sshd_config = stdout.read().decode('utf-8')
        if "PermitRootLogin yes" in sshd_config:
            results["vulnerable_configs"].append("SSH allows root login (PermitRootLogin yes)")
        if "PasswordAuthentication yes" in sshd_config:
            results["vulnerable_configs"].append("SSH allows password authentication (PasswordAuthentication yes)")
            
        # 3. Package Scanning
        stdin, stdout, stderr = client.exec_command("which dpkg && dpkg -l | wc -l || (which rpm && rpm -qa | wc -l)")
        pkg_count = stdout.read().decode('utf-8').strip()
        if pkg_count.isdigit():
            results["installed_packages_count"] = int(pkg_count)
            
    except paramiko.AuthenticationException:
        results["status"] = "failed"
        results["errors"].append("SSH Authentication failed.")
    except Exception as e:
        results["status"] = "failed"
        results["errors"].append(f"Remote scan error: {str(e)}")
    finally:
        client.close()
        
    return results
