from socket import socket, AF_INET, SOCK_STREAM
import venv
from invoke import Context
from hvac import Client  # HashiCorp Vault Python client
import os
import subprocess
import socket
import json
import yaml
import webbrowser
import logging
from invoke import task
from dotenv import load_dotenv
from fabric import task

# Load environment variables from a .env file if it exists
load_dotenv()

# Configure logging
logging.basicConfig(
    filename="mvp_setup.log",
    filemode="a",
    format="%(asctime)s - %(levelname)s - %(message)s",
    level=logging.INFO,
)

# Helper to run shell commands


def run_command(c, command, description=None):
    if description:
        print(description)
    c.run(command, pty=True)


@task
def setup_autobackup(c, file_path="fabfile.py", backup_dir="backups"):
    """
    Set up an automatic backup system for critical files.
    Args:
        file_path: The file to back up (default: fabfile.py).
        backup_dir: Directory to store backups (default: backups).
    """
    # Ensure backup directory exists
    os.makedirs(backup_dir, exist_ok=True)
    backup_file = os.path.join(backup_dir,
                               f"{os.path.basename(file_path)}.bak")

    print(f"Creating a backup of {file_path} at {backup_file}...")
    c.run(f"cp {file_path} {backup_file}", warn=True)
    print("Backup completed.")


@task
def git_initialize(c):
    """
    Initialize Git for version control if not already set up.
    """
    if not os.path.exists(".git"):
        print("Initializing Git repository...")
        c.run("git init", warn=True)
        print("Git repository initialized.")
    else:
        print("Git repository already exists.")

    # Add .gitignore to prevent committing unnecessary files
    print("Setting up .gitignore...")
    with open(".gitignore", "a") as f:
        f.write("\n# Swap and backup files\n*.swp\n*.bak\nbackups/\n")
    c.run("git add .gitignore && git commit -m 'Add .gitignore'", warn=True)


@task
def commit_changes(c, message="Auto-backup before edit"):
    """
    Commit changes to Git with a specified message.
    Args:
        message: Commit message (default: Auto-backup before edit).
    """
    print("Committing changes...")
    c.run("git add fabfile.py", warn=True)
    c.run(f"git commit -m '{message}'", warn=True)
    print("Changes committed to Git.")


@task
def validate_and_recover(c):
    """
    Validate the file and recover from swap files if needed.
    """
    swap_file = ".fabfile.py.swp"
    if os.path.exists(swap_file):
        print("Swap file detected. Attempting to recover...")
        c.run("vim -r fabfile.py", warn=True)
        print("File recovered from swap file.")
    else:
        print("No swap file found. Validation complete.")


@task
def edit_with_backup(c, file_path="fabfile.py"):
    """
    Backup and validate before editing a file.
    Args:
        file_path: The file to edit (default: fabfile.py).
    """
    # Backup before editing
    setup_autobackup(c, file_path)

    # Validate and check for swap files
    validate_and_recover(c)

    # Open file for editing
    print(f"Opening {file_path} for editing...")
    c.run(f"vim {file_path}", warn=True)

    # Commit changes after editing
    commit_changes(c, message="Edit completed and saved.")


@task
def full_safety_workflow(c):
    """
    Run a full workflow: backup, validate, edit, and commit changes.
    """
    print("Starting full safety workflow...")
    file_path = "fabfile.py"

    # Initialize Git if not already done
    git_initialize(c)

    # Backup, validate, and edit
    edit_with_backup(c, file_path)

    print("Safety workflow complete!")


@task
def prepare_env(c, node_ip, branch="main"):
    """
    Prepare the environment by syncing the repository on the remote node.

    Args:
        node_ip: The IP address of the remote node.
        branch: The branch to sync (default: main).
    """
    repo_path = "~/fabric-tasks-repo"
    remote_user = "admin"
    branch_option = f"--branch {branch}" if branch else ""

    print(f"Preparing environment on {node_ip}...")

    # Ensure the repository is updated on the remote node
    try:
        c.run(
            f"ssh {remote_user}@{node_ip} "
            f"'cd {repo_path} && git fetch --all && git checkout {branch} && git pull origin {branch}'",
            warn=True,
        )
        print(f"Repository updated to branch '{branch}' on {node_ip}.")
    except Exception as e:
        print(f"Failed to fetch branch '{branch}': {e}")
        raise

    # Sync the repository from remote to local (if needed)
    c.run(
        f"rsync -avz --exclude='.git/' {remote_user}@{node_ip}:{repo_path}/ {repo_path}/")
    print(f"Repository synced successfully from {node_ip} to local.")


@task
def setup_docker_swarm(c):
    """
    Set up Docker Swarm, build necessary images, and deploy the stack.

    Args:
        c: Context for running commands.
    """
    # Set up Docker registry and compose file
    registry_url = os.getenv(
        "DOCKER_REPO_URL",
        "ghcr.io/xowlpost/repo-name:latest")
    docker_compose_file = "docker-compose.yml"

    print("Grafana will be proxied at: /grafana/")
    print("Prometheus will be proxied at: /prometheus/")

    # Initialize Docker Swarm
    print("Initializing Docker Swarm...")
    try:
        c.run("docker swarm init", warn=True)
    except Exception as e:
        print("Swarm might already be initialized. Skipping initialization.")

    # Generate tokens for worker and manager nodes
    print("Generating join tokens...")
    try:
        worker_token = c.run(
            "docker swarm join-token worker -q",
            warn=True).stdout.strip()
        manager_token = c.run(
            "docker swarm join-token manager -q",
            warn=True).stdout.strip()
        print(f"Worker Token: {worker_token}")
        print(f"Manager Token: {manager_token}")
    except Exception as e:
        print(f"Error generating tokens: {e}")
        return

    # Check and build the AppAgent image if not available
    print(f"Checking Docker image: {registry_url}...")
    try:
        c.run(f"docker image inspect {registry_url}", hide=True)
        print(f"Docker image {registry_url} found locally.")
    except Exception:
        print(
            f"Docker image {registry_url} not found locally. Building and pushing...")
        try:
            c.run(f"docker build -t {registry_url} .")
            c.run(f"docker push {registry_url}")
        except Exception as e:
            print(f"Failed to build or push the image: {e}")
            return

    # Deploy the stack using docker-compose.yml
    print("Deploying services using docker-compose.yml...")
    try:
        c.run(f"docker stack deploy -c {docker_compose_file} xo-stack")
        print("Services deployed successfully.")
    except Exception as e:
        print(f"Error deploying Docker stack: {e}")
        return

    # Verify services after deployment
    print("Verifying services...")
    try:
        c.run("docker stack ps xo-stack", warn=True)
        print("Services are running successfully.")
    except Exception as e:
        print(f"Failed to verify services: {e}")

    print("Docker Swarm setup complete.")


@task
def deploy_service(c, service_name):
    """
    Deploy or update a specific service in the Docker Swarm.
    """
    print(f"Deploying or updating service: {service_name}...")
    c.run(f"docker service update --force xo-stack_{service_name}", warn=True)
    print(f"Service {service_name} updated successfully.")


@task
def setup_emu_reverse_proxy(
        c, ssh_user="admin", node_ip="192.168.1.21", local_port="8080"):
    """
    Set up the Android Emulator reverse proxy and SSH tunnel.
    """
    print("Configuring Nginx for reverse proxy...")

    nginx_config = f"""
server {{
    listen 80;
    server_name {node_ip};

    location /emu/ {{
        proxy_pass http://127.0.0.1:6080/;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
    }}
}}
"""

    # Create the directory if it doesn't exist
    c.sudo("mkdir -p /etc/nginx/sites-available")
    c.sudo("mkdir -p /etc/nginx/sites-enabled")

    # Write the Nginx configuration to a temporary file
    temp_file = "/tmp/android-emulator"
    c.run(f'echo "{nginx_config}" > {temp_file}')

    # Use sudo to move the file to the Nginx sites-available directory
    c.sudo(f"mv {temp_file} /etc/nginx/sites-available/android-emulator")

    # Use sudo to create a symlink in sites-enabled
    c.sudo("ln -s /etc/nginx/sites-available/android-emulator /etc/nginx/sites-enabled/")

    # Use sudo to test and reload Nginx
    c.sudo("nginx -t && systemctl reload nginx")

    print("Reverse proxy configured.")

    print(f"You can now access the emulator UI at http://{node_ip}/emu/")


@task
def validate_nginx(c):
    """Check NGINX configuration and health"""
    print("Validating NGINX configuration...")
    c.run("sudo nginx -t", warn=True)  # Tests the NGINX config
    # Checks if NGINX responds on port 8080
    c.run("curl -I http://localhost:8080", warn=True)


@task
def setup_android_emulator(c, bind_address="0.0.0.0", vnc_port=None):
    """
    Set up Android Emulator with external VNC access.

    Args:
        bind_address: Address to bind the emulator (default: 0.0.0.0 for external access).
        vnc_port: Port for VNC access (default: dynamically assigned if not provided).
    """
    container_name = "android-emulator-xo-node-admin"
    image_name = "budtmo/docker-android"

    # Dynamically assign a port if not provided
    if not vnc_port:
        vnc_port = get_available_port(start=5000, end=6000)

    # Stop and remove any existing emulator container
    c.run(f"docker stop {container_name} || true", warn=True)
    c.run(f"docker rm {container_name} || true", warn=True)

    # Run the Android emulator
    c.run(
        f"docker run -d --name {container_name} "
        f"-p {bind_address}:{vnc_port}:6080 "
        f"-e DEVICE='Nexus 5' -e APPIUM=true {image_name}",
        pty=True,
    )

    print(f"Android Emulator is running on {bind_address}:{vnc_port} for VNC.")


@task
def setup_iptables(c, external_access=False):
    """
    Configure iptables rules for external access to services.
    Args:
        external_access: If True, setup forwarding for external devices.
    """
    print("Configuring iptables rules...")
    if external_access:
        # Allow forwarding for emulator services
        services = [
            {"port": 6080, "protocol": "tcp"},  # VNC
            {"port": 5554, "protocol": "tcp"},  # Emulator console
            {"port": 5555, "protocol": "tcp"},  # ADB
            {"port": 4723, "protocol": "tcp"},  # Appium
        ]
        for service in services:
            c.run(
                f"sudo iptables -A INPUT -p {service['protocol']} --dport {service['port']} -j ACCEPT",
                warn=True,
            )
        print("External access enabled via iptables.")
    else:
        print("External access is disabled; no iptables changes made.")


@task
def setup_dashboard(c, external_access=False):
    """
    Setup Prometheus, Grafana, and NGINX for the dashboard.
    Args:
        external_access: If True, allow access via external IPs.
    """
    print("Setting up the full dashboard...")

    bind_address = "0.0.0.0" if external_access else "127.0.0.1"

    # Prometheus Setup
    setup_prometheus(c, bind_address)

    # Grafana Setup
    setup_grafana(c, bind_address)

    # NGINX Proxy
    setup_nginx(c, bind_address)

    # Update iptables rules if needed
    setup_iptables(c, external_access)

    print("Dashboard setup complete!")


@task
def setup_prometheus(c):
    """
    Set up Prometheus with dynamic environment variable support and container validation.

    Uses environment variables:
    - PROMETHEUS_CONFIG_PATH: Path to the Prometheus configuration file (default: ./prometheus.yml).
    - PROMETHEUS_BIND_ADDRESS: Address to bind Prometheus (default: 127.0.0.1).
    """
    # Fetch configuration path and bind address from environment variables
    config_path = os.getenv("PROMETHEUS_CONFIG_PATH", "./prometheus.yml")
    bind_address = os.getenv("PROMETHEUS_BIND_ADDRESS", "127.0.0.1")

    config_file = os.path.abspath(config_path)

    try:
        # Ensure configuration file exists or create one dynamically
        if not os.path.exists(config_file):
            print(
                f"Configuration file not found at {config_file}. Creating a default file...")
            try:
                with open(config_file, "w") as f:
                    f.write("global:\n  scrape_interval: 15s\n")
                print(f"Default configuration file created at {config_file}.")
            except Exception as e:
                print(
                    f"Failed to create default configuration file. Error: {e}")
                return

        print(
            f"Setting up Prometheus with configuration file: {config_file}...")

        # Stop and remove any existing Prometheus container
        try:
            c.run("docker stop prometheus || true", warn=True)
            c.run("docker rm prometheus || true", warn=True)
            print("Stopped and removed any existing Prometheus container.")
        except Exception as e:
            print(
                f"Failed to stop/remove existing Prometheus container. Error: {e}")

        # Run Prometheus
        try:
            c.run(
                f"docker run -d --name prometheus "
                f"-p {bind_address}:9090:9090 "
                f"-v {config_file}:/etc/prometheus/prometheus.yml "
                f"prom/prometheus:latest",
                pty=True,
            )
            print(f"Prometheus is now running on {bind_address}:9090")
        except Exception as e:
            print(f"Failed to start Prometheus container. Error: {e}")
            return

        # Validate that the Prometheus container is running
        try:
            result = c.run(
                "docker ps --filter name=prometheus --format '{{.Names}}'",
                hide=True,
                warn=True)
            if result.ok and "prometheus" in result.stdout.strip():
                print(
                    f"Prometheus container is running successfully as '{result.stdout.strip()}'.")
            else:
                print(
                    "Prometheus container did not start successfully. Please check the logs.")
        except Exception as e:
            print(
                f"Error while validating Prometheus container status. Error: {e}")

    except Exception as e:
        print(f"Unexpected error during Prometheus setup: {e}")


@task
def setup_grafana(c):
    """
    Set up Grafana container and expose the specified port.
    """
    grafana_port = os.getenv("GRAFANA_PORT", "3000")

    print(f"Setting up Grafana on port {grafana_port}...")
    try:
        # Pull the Grafana container
        c.run("docker pull grafana/grafana:latest", pty=True)

        # Stop and remove any existing Grafana container
        c.run("docker stop grafana || true", warn=True)
        c.run("docker rm grafana || true", warn=True)

        # Run Grafana container
        c.run(
            f"docker run -d --name grafana "
            f"-p {grafana_port}:3000 "
            f"grafana/grafana:latest",
            pty=True,
        )
        print(f"Grafana is running on http://localhost:{grafana_port}")
    except Exception as e:
        print(f"Failed to set up Grafana. Error: {e}")


grafana_path = os.getenv("GRAFANA_PROXY_PATH", "/grafana/")
prometheus_path = os.getenv("PROMETHEUS_PROXY_PATH", "/prometheus/")

print(f"Grafana will be proxied at: {grafana_path}")
print(f"Prometheus will be proxied at: {prometheus_path}")


@task
def setup_service(c, service_name, service_port, proxy_path):
    """
    Generic task to set up and configure a service.
    Args:
        service_name: Name of the service (e.g., 'dashboard').
        service_port: Port on which the service will run.
        proxy_path: Path for reverse proxy in NGINX (e.g., '/dashboard/').
    """
    print(
        f"Setting up {service_name} on port {service_port} with proxy path {proxy_path}...")
    try:
        # Example: Docker service setup (replace with actual service commands)
        c.run(
            f"docker run -d --name {service_name} -p {service_port}:{service_port} {service_name}:latest",
            pty=True)
        print(f"{service_name.capitalize()} is running on port {service_port}. Accessible via proxy path: {proxy_path}")
    except Exception as e:
        print(f"Failed to set up {service_name}. Error: {e}")


@task
def run_container_with_sshfs(c, shield_user="shield-user", shield_ip="192.168.1.100",
                             container_name="my-container", container_mount="/models"):
    """
    Mount Shield via SSHFS and run a Docker container with the mounted directory.

    Args:
        shield_user: SSH username for Shield.
        shield_ip: IP address of Shield.
        container_name: Name of the Docker container to run.
        container_mount: Path inside the container where the directory will be mounted.
    """
    local_mount = "/mnt/shield/models"

    print(f"Mounting Shield directory via SSHFS at {local_mount}...")
    try:
        # Ensure the local mount point exists
        c.run(f"mkdir -p {local_mount}", warn=True)

        # Mount via SSHFS
        c.run(
            f"sshfs {shield_user}@{shield_ip}:/mnt/shield/models/nlp_model {local_mount}",
            pty=True)

        print(
            f"Running container '{container_name}' with mount {local_mount} -> {container_mount}...")
        c.run(
            f"docker run -d --name {container_name} "
            f"-v {local_mount}:{container_mount} "
            f"container-image-name:latest",  # Replace with actual image name
            pty=True,
        )
        print(
            f"Container '{container_name}' is running with {local_mount} mounted at {container_mount}.")
    except Exception as e:
        print(
            f"Failed to run container with Shield mounted via SSHFS. Error: {e}")
    finally:
        # Unmount SSHFS after the task
        print(f"Unmounting SSHFS from {local_mount}...")
        c.run(f"fusermount -u {local_mount}", warn=True)


load_dotenv()  # Load .env variables


@task
def setup_nfs_export(c):
    """
    Set up NFS exports on the NFS server (xo-node).
    """
    nfs_path = os.getenv("NFS_EXPORT_PATH", "/mnt/shield/models/nlp_model")
    mount_options = os.getenv(
        "NFS_MOUNT_OPTIONS",
        "rw,sync,no_subtree_check,no_root_squash")

    print(
        f"Setting up NFS export for {nfs_path} with options: {mount_options}")
    try:
        # Ensure directory exists
        c.run(f"sudo mkdir -p {nfs_path}", warn=True)

        # Remove duplicate entries without `sed`
        c.run(
            f"sudo grep -v '{nfs_path}' /etc/exports > /tmp/exports.tmp && sudo mv /tmp/exports.tmp /etc/exports",
            warn=True)

        # Add export entry
        c.run(
            f'echo "{nfs_path} *({mount_options})" | sudo tee -a /etc/exports',
            warn=True)

        # Apply changes and restart NFS service
        c.run("sudo exportfs -ra", warn=True)
        c.run("sudo systemctl restart nfs-kernel-server", warn=True)
        print("NFS export setup completed.")
    except Exception as e:
        print(f"Failed to set up NFS export. Error: {e}")


@task
def mount_nfs(c, is_client="yes"):
    """
    Mount the NFS share on the client or server with fallback for NFS versions.

    Args:
        is_client: Whether this is being run on the client (`yes` or `no`).
    """
    nfs_server = os.getenv("NFS_SERVER_IP", "192.168.1.21")
    export_path = os.getenv("NFS_EXPORT_PATH", "/mnt/shield/models/nlp_model")
    local_mount = os.getenv("NFS_MOUNT_PATH", "/mnt/shield/models")
    mount_options = os.getenv("NFS_MOUNT_OPTIONS", "rw,sync,no_subtree_check")

    if is_client.lower() == "yes":
        print(
            f"Mounting NFS share {export_path} from server {nfs_server} to {local_mount}...")
        try:
            # Ensure the local mount directory exists
            c.run(f"sudo mkdir -p {local_mount}", warn=True)

            # Try with default version
            try:
                c.run(
                    f"sudo mount -t nfs -o {mount_options},vers=4 {nfs_server}:{export_path} {local_mount}",
                    warn=True)
                print(f"NFS share mounted at {local_mount}. (vers=4)")
            except Exception as e:
                print(f"Failed with vers=4, retrying with vers=3...")
                c.run(
                    f"sudo mount -t nfs -o {mount_options},vers=3 {nfs_server}:{export_path} {local_mount}",
                    warn=True)
                print(f"NFS share mounted at {local_mount}. (vers=3)")
        except Exception as e:
            print(f"Failed to mount NFS share. Error: {e}")
    else:
        print("Skipping NFS mount (not running on client).")


@task
def setup_nfs_server(c):
    """
    Set up NFS server, resolve ordering cycles, and configure exports.
    """
    nfs_path = os.getenv("NFS_EXPORT_PATH", "/mnt/shield/models/nlp_model")
    mount_options = os.getenv("NFS_MOUNT_OPTIONS", "rw,sync,no_subtree_check")

    print(f"Setting up NFS server for export path: {nfs_path}...")
    try:
        # Ensure the export directory exists
        local_c = Context()  # Use Invoke Context for local commands
        local_c.run(f"sudo mkdir -p {nfs_path}", warn=True)

        # Remove duplicate export entries
        local_c.run(
            f"sudo grep -v '{nfs_path}' /etc/exports > /tmp/exports.tmp && sudo mv /tmp/exports.tmp /etc/exports",
            warn=True)

        # Add the export entry
        local_c.run(
            f'echo "{nfs_path} *({mount_options})" | sudo tee -a /etc/exports',
            warn=True)

        # Apply changes and restart the NFS service
        local_c.run("sudo exportfs -ra", warn=True)
        local_c.run("sudo systemctl restart nfs-server", warn=True)

        print("NFS server setup completed.")
    except Exception as e:
        print(f"Failed to set up NFS server. Error: {e}")


@task
def mount_nfs_client(c):
    """
    Mount NFS share on the client and ensure it's persistent.
    """
    nfs_server = os.getenv("NFS_SERVER_IP", "192.168.1.21")
    export_path = os.getenv("NFS_EXPORT_PATH", "/mnt/shield/models/nlp_model")
    local_mount = os.getenv("NFS_MOUNT_PATH", "/mnt/shield/models")
    mount_options = os.getenv("NFS_MOUNT_OPTIONS", "rw,sync,no_subtree_check")

    print(
        f"Mounting NFS share {export_path} from server {nfs_server} to {local_mount}...")
    try:
        # Ensure the local mount directory exists
        c.run(f"sudo mkdir -p {local_mount}", warn=True)

        # Mount the NFS share
        c.run(
            f"sudo mount -t nfs -o {mount_options} {nfs_server}:{export_path} {local_mount}",
            warn=True)

        # Add to /etc/fstab for persistence
        c.run(
            f'echo "{nfs_server}:{export_path} {local_mount} nfs {mount_options} 0 0" | sudo tee -a /etc/fstab',
            warn=True)
        print(f"NFS share mounted and made persistent at {local_mount}.")
    except Exception as e:
        print(f"Failed to mount NFS share. Error: {e}")


@task
def test_nfs_setup(c):
    """
    Test NFS server and client configuration.
    """
    nfs_server = os.getenv("NFS_SERVER_IP", "192.168.1.21")
    export_path = os.getenv("NFS_EXPORT_PATH", "/mnt/shield/models/nlp_model")
    local_mount = os.getenv("NFS_MOUNT_PATH", "/mnt/shield/models")

    print("Testing NFS setup...")
    try:
        # Check server-side exports
        print("Checking NFS server exports:")
        c.run("sudo exportfs -v", warn=True)

        # Check if the share is mounted on the client
        print(f"Verifying mount point on client: {local_mount}")
        c.run(f"df -h | grep {local_mount}", warn=True)

        # Test writing to the mount point
        c.run(
            f"echo 'Test NFS Setup' | sudo tee {local_mount}/nfs_test.txt",
            warn=True)
        c.run(f"cat {local_mount}/nfs_test.txt", warn=True)

        print("NFS setup is functional.")
    except Exception as e:
        print(f"Failed to test NFS setup. Error: {e}")


@task
def sync_to_xo_node(c):
    """
    Sync local data to xo-node's NFS share dynamically.
    """
    sync_user = os.getenv("SYNC_USER", "admin")
    sync_host = os.getenv("SYNC_HOST", "xo-node")
    local_path = os.getenv("SYNC_LOCAL_PATH", "/mnt/shield/models/nlp_model")
    remote_path = os.getenv("SYNC_REMOTE_PATH", "/mnt/shield/models/nlp_model")

    print(f"Syncing {local_path} to {sync_user}@{sync_host}:{remote_path}...")
    try:
        c.run(
            f"rsync -avz {local_path} {sync_user}@{sync_host}:{remote_path} --rsync-path='sudo rsync'")
        print("Sync completed successfully.")
    except Exception as e:
        print(f"Failed to sync data. Error: {e}")


@task
def setup_monitoring(c):
    """
    Set up Prometheus and Grafana for monitoring AppAgent and Emulator metrics.
    """
    print("Setting up Prometheus and Grafana...")

    prometheus_config_path = "prometheus.yml"

    # Ensure prometheus.yml is not a directory
    if os.path.isdir(prometheus_config_path):
        raise RuntimeError(
            f"{prometheus_config_path} is a directory. Please remove or rename it.")

    # Prometheus configuration
    prometheus_config = """
    global:
      scrape_interval: 15s

    scrape_configs:
      - job_name: 'appagent'
        static_configs:
          - targets: ['localhost:5003']
      - job_name: 'android-emulator'
        static_configs:
          - targets: ['localhost:6081']
    """
    # Write Prometheus config file
    with open(prometheus_config_path, "w") as f:
        f.write(prometheus_config)
    print("Prometheus configuration file created.")

    # Create Prometheus container
    c.run(
        "docker run -d --name prometheus -p 9090:9090 -v $PWD/prometheus.yml:/etc/prometheus/prometheus.yml prom/prometheus",
        pty=True,
    )
    print("Prometheus is running on http://localhost:9090")

    # Create Grafana container
    c.run(
        "docker run -d --name grafana -p 3000:3000 grafana/grafana",
        pty=True,
    )
    print("Grafana is running on http://localhost:3000")


# Import necessary modules

# Dynamically get free ports

def get_free_port():
    """
    Find and return a free port on the host machine.
    """
    import socket
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(('', 0))
        return s.getsockname()[1]


# Define default port variables
nginx_port = get_free_port()
emulator_port = get_free_port()
appagent_port = get_free_port()


def run_command(command, capture_output=False):
    """
    Run a shell command dynamically with optional output capture.
    """
    try:
        result = subprocess.run(
            command, shell=True, text=True, check=True, capture_output=capture_output
        )
        if capture_output:
            return result.stdout.strip()
    except subprocess.CalledProcessError as e:
        print(f"Error running command: {command}")
        raise

# Task to update docker-compose.yml dynamically


@task
def update_compose(c, nginx_port=nginx_port,
                   emulator_port=emulator_port, appagent_port=appagent_port):
    """
    Dynamically updates the docker-compose.yml file with provided ports.
    """
    import yaml

    compose_file = "docker-compose.yml"

    print("Loading docker-compose.yml...")
    try:
        with open(compose_file, "r") as f:
            compose_data = yaml.safe_load(f)
    except FileNotFoundError:
        print(f"Error: {compose_file} not found!")
        return

    print("Updating ports in docker-compose.yml...")
    # Update NGINX ports
    if "nginx" in compose_data["services"]:
        compose_data["services"]["nginx"]["ports"] = [f"{nginx_port}:80"]

    # Update Android Emulator ports
    if "android-emulator" in compose_data["services"]:
        compose_data["services"]["android-emulator"]["ports"] = [
            f"{emulator_port}:6080"]

    # Update AppAgent ports
    if "appagent" in compose_data["services"]:
        compose_data["services"]["appagent"]["ports"] = [
            f"{appagent_port}:5000"]

    print("Writing updated docker-compose.yml...")
    with open(compose_file, "w") as f:
        yaml.dump(compose_data, f, default_flow_style=False)

    print("docker-compose.yml updated successfully.")


def stop_and_remove_container(container_name):
    """
    Stops and removes a Docker container if it exists.
    """
    try:
        # Stop the container if running
        run_command(f"docker stop {container_name}", capture_output=True)
        print(f"Stopped container: {container_name}")
    except subprocess.CalledProcessError:
        print(f"Container {container_name} is not running.")

    try:
        # Remove the container if it exists
        run_command(f"docker rm {container_name}", capture_output=True)
        print(f"Removed container: {container_name}")
    except subprocess.CalledProcessError:
        print(f"Container {container_name} does not exist.")


@task
def setup_nginx(c, nginx_config_path="./nginx.conf"):
    """
    Deploy, install, and reload NGINX with the specified configuration file.

    Args:
        c: Fabric context object for running commands.
        nginx_config_path: Path to the NGINX configuration file (default: ./nginx.conf).
    """
    try:
        # Resolve full path of the configuration file
        nginx_config_file = os.path.abspath(nginx_config_path)

        # Check if NGINX configuration file exists
        if not os.path.exists(nginx_config_file):
            raise FileNotFoundError(
                f"NGINX configuration file not found at {nginx_config_file}")

        print(f"Using NGINX configuration file: {nginx_config_file}")

        # Check if NGINX is installed, install it if missing
        print("Checking if NGINX is installed...")
        if c.run("nginx -v", warn=True, hide=True).failed:
            print("NGINX is not installed. Installing...")
            c.sudo("apt update && apt install -y nginx", warn=True)
            c.sudo("systemctl enable nginx", warn=True)
            c.sudo("systemctl start nginx", warn=True)
            print("NGINX installed and started.")
        else:
            print("NGINX is already installed.")

        # Stop and remove any existing NGINX container
        print("Stopping and removing existing NGINX container (if any)...")
        c.run("docker stop nginx || true", warn=True)
        c.run("docker rm nginx || true", warn=True)

        # Deploy the NGINX configuration via Docker
        print("Deploying NGINX with the specified configuration...")
        c.run(
            f"docker run -d --name nginx "
            f"-p 8080:8080 "
            f"-v {nginx_config_file}:/etc/nginx/nginx.conf:ro "
            f"nginx:latest",
            pty=True,
        )
        print("NGINX container started.")

        # Validate that the NGINX container is running
        print("Validating NGINX container status...")
        result = c.run(
            "docker ps --filter name=nginx --format '{{.Names}}'",
            warn=True,
            hide=True)
        if result.ok and "nginx" in result.stdout.strip():
            print(
                f"NGINX container is running successfully as '{result.stdout.strip()}'.")
        else:
            raise RuntimeError(
                "NGINX container failed to start. Please check the logs.")

        # Provide final confirmation
        print("NGINX is running and accessible at: http://<xo-node-ip>:8080")

    except FileNotFoundError as e:
        print(f"Configuration Error: {e}")
    except RuntimeError as e:
        print(f"Validation Error: {e}")
    except Exception as e:
        print(f"Unexpected error during NGINX setup: {e}")


# HashiCorp Vault setup (adjust for your setup)
VAULT_ADDR = "http://127.0.0.1:8200"  # Vault server address
VAULT_TOKEN = os.getenv("VAULT_TOKEN", "root")  # Replace with your token


def get_docker_credentials():
    """
    Fetch Docker credentials securely from HashiCorp Vault.
    """
    try:
        client = Client(url=VAULT_ADDR, token=VAULT_TOKEN)
        secrets = client.secrets.kv.read_secret_version(
            path="secret/docker")["data"]["data"]
        return secrets["DOCKER_USERNAME"], secrets["DOCKER_PASSWORD"]
    except Exception as e:
        raise RuntimeError(
            f"Failed to fetch Docker credentials from Vault: {e}")


@task
def docker_login(c):
    """
    Authenticate with Docker using credentials securely stored in HashiCorp Vault.
    """
    try:
        docker_username, docker_password = get_docker_credentials()
        print(f"Logging into Docker repository as '{docker_username}'...")

        # Authenticate with Docker
        c.run(
            f"echo {docker_password} | docker login ghcr.io --username {docker_username} --password-stdin",
            hide=True,
        )
        print("Docker login successful.")
    except Exception as e:
        print(f"Failed to log in to Docker. Error: {e}")


@task
def setup_vault_container(c):
    """
    Pull and run HashiCorp Vault in dev mode inside a Docker container.
    """
    try:
        # Pull the Vault image
        print("Pulling the Vault container...")
        c.run("docker pull hashicorp/vault:latest", pty=True)

        # Stop and remove any existing Vault container
        print("Stopping and removing existing Vault container (if any)...")
        c.run("docker stop vault-dev || true", warn=True)
        c.run("docker rm vault-dev || true", warn=True)

        # Run Vault in dev mode
        print("Running Vault in dev mode...")
        c.run(
            "docker run -d --name vault-dev "
            "-p 8200:8200 "
            "-e VAULT_DEV_ROOT_TOKEN_ID=root "
            "hashicorp/vault:latest server -dev",
            pty=True,
        )
        print("Vault dev server is running on http://127.0.0.1:8200")
    except Exception as e:
        print(f"Failed to set up Vault container. Error: {e}")


@task
def unseal_vault(c):
    """
    Unseal Vault dev server and export root token.
    """
    try:
        # Set Vault environment variables
        os.environ["VAULT_ADDR"] = "http://127.0.0.1:8200"
        os.environ["VAULT_TOKEN"] = "root"
        print("Vault environment variables configured.")

        # Verify Vault status
        print("Checking Vault status...")
        result = c.run(
            "curl --silent http://127.0.0.1:8200/v1/sys/health",
            warn=True)
        if "sealed" in result.stdout:
            print("Vault is sealed. (In dev mode, it should not be sealed.)")
        else:
            print("Vault is unsealed and ready to use.")

        print("Vault root token: root")
    except Exception as e:
        print(f"Failed to unseal Vault. Error: {e}")


@task
def setup_virtualenv(c, env_name=None, requirements="requirements.txt"):
    """
    Set up a Python virtual environment dynamically and install dependencies.

    Args:
        c: Fabric context object for running commands.
        env_name: Name of the virtual environment directory (defaults to ENV_NAME in .env or 'default_env').
        requirements: Path to the requirements file for installing packages (default: requirements.txt).
    """
    try:
        # Dynamically determine the environment name
        if not env_name:
            # Use ENV_NAME from .env, fallback to 'default_env'
            env_name = os.getenv("ENV_NAME", "default_env")

        # Create virtual environment
        if not os.path.exists(env_name):
            print(f"Creating virtual environment: {env_name}")
            venv.create(env_name, with_pip=True)
        else:
            print(f"Virtual environment '{env_name}' already exists.")

        # Activate and install requirements
        if os.path.exists(requirements):
            print(f"Installing dependencies from {requirements}...")
            c.run(
                f"source {env_name}/bin/activate && pip install -r {requirements}",
                pty=True,
            )
            print(f"Virtual environment '{env_name}' is ready.")
        else:
            print(
                f"No requirements file found at {requirements}. Skipping dependency installation.")

    except Exception as e:
        print(f"Failed to set up virtual environment. Error: {e}")


@task
def pull_docker_image(c):
    """
    Pull the Docker image specified in .env file.
    """
    docker_repo_url = os.getenv("DOCKER_REPO_URL")

    if not docker_repo_url:
        print("Error: DOCKER_REPO_URL is missing in .env file.")
        return

    print(f"Pulling Docker image: {docker_repo_url}")
    try:
        c.run(f"docker pull {docker_repo_url}", pty=True)
        print(f"Successfully pulled image: {docker_repo_url}")
    except Exception as e:
        print(f"Failed to pull Docker image. Error: {e}")


@task
def run_docker_container(c, container_name="my_container",
                         port_mapping="8080:80"):
    """
    Run a Docker container from the pulled image.

    Args:
        container_name: Name of the Docker container to run.
        port_mapping: Port mapping for the container (e.g., "8080:80").
    """
    docker_repo_url = os.getenv("DOCKER_REPO_URL")

    if not docker_repo_url:
        print("Error: DOCKER_REPO_URL is missing in .env file.")
        return

    print(
        f"Running Docker container '{container_name}' from image: {docker_repo_url}")
    try:
        c.run(
            f"docker run -d --name {container_name} -p {port_mapping} {docker_repo_url}",
            pty=True)
        print(
            f"Container '{container_name}' is running on port {port_mapping}.")
    except Exception as e:
        print(f"Failed to run Docker container. Error: {e}")


@task
def full_dashboard_setup(c):
    """
    Dynamically set up Prometheus, Grafana, and NGINX for the dashboard.
    """
    print("Setting up the full dashboard...")
    setup_prometheus(c)
    setup_grafana(c)
    setup_nginx(c)
    print("Full dashboard setup complete!")
    print("Access components:")
    print("- Prometheus: http://localhost:8080/prometheus/")
    print("- Grafana: http://localhost:8080/grafana/")


@task
def update_main_py(c):
    """
    Update the main.py file in the AppAgent directory to include the required endpoints.
    """
    appagent_path = "./appagent/main.py"  # Adjust the path if necessary
    main_py_content = """
from flask import Flask, jsonify

app = Flask(__name__)

@app.route("/")
def root():
    return jsonify({"message": "AppAgent is running!"}), 200

@app.route("/health")
def health():
    return jsonify({"status": "healthy"}), 200

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)
"""
    print("Updating main.py file...")
    with open(appagent_path, "w") as f:
        f.write(main_py_content)
    print(f"Updated {appagent_path} successfully.")


@task(pre=[update_main_py])
def rebuild_and_restart_appagent(c):
    """
    Rebuild and restart the AppAgent Docker container.
    """
    print("Rebuilding AppAgent Docker container...")
    c.run("docker build -t appagent ./appagent", pty=True)

    print("Stopping any running AppAgent container...")
    c.run("docker rm -f appagent || true", warn=True, pty=True)

    print("Starting the AppAgent container...")
    appagent_port = os.getenv("APPAGENT_PORT", "5002")
    c.run(
        f"docker run -d -p {appagent_port}:5000 --name appagent appagent",
        pty=True)
    print(f"AppAgent container is running on port {appagent_port}.")


@task
def update_and_restart_appagent(c):
    """
    Update main.py, rebuild, and restart the AppAgent container.
    """
    update_main_py(c)
    rebuild_and_restart_appagent(c)


def get_available_port(start=5000, end=6000):
    """
    Find an available port in the given range.
    """
    for port in range(start, end):
        with socket(AF_INET, SOCK_STREAM) as s:
            if s.connect_ex(("localhost", port)) != 0:
                return port
    raise RuntimeError("No available ports found.")


@task
def resolve_conflicts_and_allocate_ports(c):
    """
    Resolve container conflicts and dynamically allocate free ports for services.
    """
    print("Resolving container conflicts...")

    # List of conflicting containers
    containers = ["appagent", "android-emulator", "nginx"]
    for container in containers:
        try:
            c.run(f"docker rm -f {container}", warn=True, pty=True)
            print(f"Removed container: {container}")
        except Exception as e:
            print(f"Could not remove container: {container}. Error: {e}")

    print("Allocating free ports dynamically...")
    free_ports = {}
    services = [
        "NGINX_PORT",
        "EMULATOR_PORT",
        "APPMANAGER_PORT",
        "APPIUM_PORT",
        "VNC_PORT"]

    for service in services:
        free_ports[service] = get_available_port()

    # Update the .env file with allocated ports
    with open(".env", "a") as env_file:
        for key, port in free_ports.items():
            env_file.write(f"{key}={port}\n")

    print(f"Allocated ports: {free_ports}")


@task
def start_emulator(c):
    """
    Start the Android Emulator dynamically, handling conflicts.
    """
    container_name = f"android-emulator-{os.getenv('HOSTNAME', 'localhost')}-{os.getenv('USER', 'user')}"
    image_name = os.getenv("ANDROID_EMULATOR_IMAGE", "budtmo/docker-android")

    # Resolve existing container conflicts
    print("Resolving conflicts for Android Emulator...")
    c.run(f"docker rm -f {container_name}", warn=True, pty=True)

    # Start the container
    emulator_port = os.getenv("EMULATOR_PORT", "6081")
    appium_port = os.getenv("APPIUM_PORT", "4723")
    vnc_port = os.getenv("VNC_PORT", "8200")
    command = (
        f"docker run -d --name {container_name} "
        f"-p {emulator_port}:6080 -p {appium_port}:4723 "
        f"-p 5554:5554 -p 5555:5555 -p {vnc_port}:8200 "
        f"-e DEVICE='Nexus 5' -e APPIUM=true {image_name}"
    )
    run_command(command)
    print(f"Emulator started. Access it at http://localhost:{emulator_port}")


@task
def debug_emulator(c):
    """
    Debug the Android Emulator container and Appium setup.
    """
    container_name = f"android-emulator-{os.getenv('HOSTNAME', 'localhost')}-{os.getenv('USER', 'user')}"
    print(f"Entering Android Emulator container: {container_name}...")
    c.run(
        f"docker exec -it {container_name} bash -c 'node -v; java -version; adb devices'",
        pty=True)
    print("If Appium fails, you can try restarting it manually:")
    c.run(
        f"docker exec -it {container_name} appium --log-level debug",
        pty=True)


@task
def validate_appagent_endpoints(c):
    """
    Validate AppAgent endpoints for / and /health.
    """
    print("Validating AppAgent endpoints...")
    try:
        response_health = run_command(
            "curl -s -o /dev/null -w '%{http_code}' http://localhost:5002/health",
            capture_output=True)
        response_root = run_command(
            "curl -s -o /dev/null -w '%{http_code}' http://localhost:5002/",
            capture_output=True)

        if response_health != "200":
            print(
                f"/health endpoint is not reachable. HTTP Status: {response_health}")
        else:
            print("/health endpoint is reachable. ✅")

        if response_root != "200":
            print(f"/ endpoint is not reachable. HTTP Status: {response_root}")
        else:
            print("/ endpoint is reachable. ✅")
    except Exception as e:
        print(f"Error during validation: {e}")


@task
def setup_env(c):
    """Create or update the .env file with default values."""
    env_file = ".env"
    default_env = {
        "HOSTNAME": os.uname().nodename,
        "USER": os.getlogin(),
        "NGINX_PORT": str(nginx_port),
        "EMULATOR_PORT": str(emulator_port),
        "APPAGENT_PORT": str(appagent_port),
    }

    if not os.path.exists(env_file):
        print(f"Creating {env_file}...")
        with open(env_file, "w") as f:
            for key, value in default_env.items():
                f.write(f"{key}={value}\n")
    else:
        print(f"{env_file} already exists. Updating missing values...")
        with open(env_file, "a") as f:
            for key, value in default_env.items():
                if key not in os.environ:
                    f.write(f"{key}={value}\n")
    print(f"{env_file} setup complete.")


@task
def resolve_conflicts(c):
    """
    Stop and remove conflicting containers.
    """
    containers = ["appagent", "android-emulator", "nginx"]
    for container in containers:
        try:
            c.run(f"docker rm -f {container}", warn=True, pty=True)
            print(f"Removed container: {container}")
        except Exception as e:
            print(
                f"No conflict for container: {container}, or error occurred: {e}")


@task
def validate_env(c):
    """Validate that required variables are present in the .env file."""
    required_vars = [
        "HOSTNAME",
        "USER",
        "NGINX_PORT",
        "EMULATOR_PORT",
        "APPAGENT_PORT"]
    missing_vars = []

    if not os.path.exists(".env"):
        raise RuntimeError(".env file is missing!")

    with open(".env", "r") as f:
        env_vars = {line.split("=")[0]: line.split(
            "=")[1].strip() for line in f if "=" in line}

    for var in required_vars:
        if var not in env_vars:
            missing_vars.append(var)

    if missing_vars:
        raise RuntimeError(
            f"Missing required variables in .env: {', '.join(missing_vars)}")

    print("All required environment variables are present.")


@task
def update_compose(c, nginx_port=nginx_port,
                   emulator_port=emulator_port, appagent_port=appagent_port):
    """Dynamically updates the docker-compose.yml file with provided ports."""
    compose_file = "docker-compose.yml"

    print("Loading docker-compose.yml...")
    try:
        with open(compose_file, "r") as f:
            compose_data = yaml.safe_load(f)
    except FileNotFoundError:
        print(f"Error: {compose_file} not found!")
        return

    print("Updating ports in docker-compose.yml...")
    if "nginx" in compose_data["services"]:
        compose_data["services"]["nginx"]["ports"] = [f"{nginx_port}:80"]
    if "android-emulator" in compose_data["services"]:
        compose_data["services"]["android-emulator"]["ports"] = [
            f"{emulator_port}:6080"]
    if "appagent" in compose_data["services"]:
        compose_data["services"]["appagent"]["ports"] = [
            f"{appagent_port}:5000"]

    print("Writing updated docker-compose.yml...")
    with open(compose_file, "w") as f:
        yaml.dump(compose_data, f, default_flow_style=False)

    print("docker-compose.yml updated successfully.")


@task
def validate_compose(c):
    """Validates the docker-compose.yml file for syntax errors."""
    result = c.run("docker-compose config", warn=True, pty=True)
    if result.failed:
        print("docker-compose.yml is invalid. Please fix the errors above.")
        raise Exception("Validation failed.")


@task
def run_compose(c):
    """Run docker-compose dynamically based on the .env file."""
    validate_env(c)
    c.run("docker-compose --env-file .env up --build -d", pty=True)


@task
def generate_refined_wezterm_config(
        c, config_path="~/.config/wezterm/wezterm.lua"):
    """
        Generate a refined WezTerm configuration for XO workflows.
            Args:
                        config_path: Path to the WezTerm config file (default: ~/.config/wezterm/wezterm.lua).
                            """
    config_path = os.path.expanduser(config_path)
    config_dir = os.path.dirname(config_path)

    # Ensure the config directory exists
    os.makedirs(config_dir, exist_ok=True)

    print(f"Generating refined WezTerm configuration at {config_path}...")

    # Refined WezTerm configuration content
    wezterm_config = f"""
                                                            local wezterm = require 'wezterm';

                                                            -- XO Branding Colors
                                                            local colors = {{
                                                              background = "#282c34",
                                                                foreground = "#abb2bf",
                                                                  cursor_bg = "#528bff",
                                                                    cursor_border = "#528bff",
                                                                      cursor_fg = "#ffffff",
                                                                        selection_bg = "#3e4451",
                                                                          selection_fg = "#abb2bf",
                                                                          }}

                                                                          return {{
                                                                            -- Basic Appearance
                                                                              font = wezterm.font("Fira Code"),
                                                                                font_size = 13.0,
                                                                                  color_scheme = "Gruvbox Dark",
                                                                                    colors = colors,
                                                                                      enable_tab_bar = true,
                                                                                        use_fancy_tab_bar = true,
                                                                                          hide_tab_bar_if_only_one_tab = false,
                                                                                            window_decorations = "RESIZE",
                                                                                              window_background_opacity = 0.95,

                                                                                                -- Startup Tabs for XO Workflows
                                                                                                  default_workspace = "XO Workspace",
                                                                                                    set_environment_variables = {{
                                                                                                        PROMETHEUS_PORT = "9090",
                                                                                                            GRAFANA_PORT = "3000",
                                                                                                                XO_NODE_IP = "192.168.1.21",
                                                                                                                  }},
                                                                                                                    default_prog = {{"/usr/bin/bash"}},

                                                                                                                      -- Dynamic Startup Tabs
                                                                                                                        default_launch = {{
                                                                                                                            {{
                                                                                                                                  label = "Fabric Tasks",
                                                                                                                                        args = {{"bash", "-c", "cd ~/fabric-tasks-repo && fab -l"}},
                                                                                                                                            }},
                                                                                                                                                {{
                                                                                                                                                      label = "XO Node Logs",
                                                                                                                                                            args = {{"ssh", "admin@192.168.1.21", "-t", "tail -f /var/log/xo-node.log"}},
                                                                                                                                                                }},
                                                                                                                                                                    {{
                                                                                                                                                                          label = "Prometheus Logs",
                                                                                                                                                                                args = {{"bash", "-c", "docker logs -f prometheus"}},
                                                                                                                                                                                    }},
                                                                                                                                                                                        {{
                                                                                                                                                                                              label = "Grafana Logs",
                                                                                                                                                                                                    args = {{"bash", "-c", "docker logs -f grafana"}},
                                                                                                                                                                                                        }},
                                                                                                                                                                                                            {{
                                                                                                                                                                                                                  label = "Port Forwarding",
                                                                                                                                                                                                                        args = {{"ssh", "-L", "9090:localhost:9090", "-L", "3000:localhost:3000", "admin@192.168.1.21"}},
                                                                                                                                                                                                                            }},
                                                                                                                                                                                                                              }},

                                                                                                                                                                                                                                -- Advanced Key Bindings
                                                                                                                                                                                                                                  keys = {{
                                                                                                                                                                                                                                      {{
                                                                                                                                                                                                                                            key = "n",
                                                                                                                                                                                                                                                  mods = "CTRL|SHIFT",
                                                                                                                                                                                                                                                        action = wezterm.action.SpawnTab("CurrentPaneDomain"),
                                                                                                                                                                                                                                                            }},
                                                                                                                                                                                                                                                                {{
                                                                                                                                                                                                                                                                      key = "w",
                                                                                                                                                                                                                                                                            mods = "CTRL|SHIFT",
                                                                                                                                                                                                                                                                                  action = wezterm.action.CloseCurrentTab({{confirm = true}}),
                                                                                                                                                                                                                                                                                      }},
                                                                                                                                                                                                                                                                                          {{
                                                                                                                                                                                                                                                                                                key = "LeftArrow",
                                                                                                                                                                                                                                                                                                      mods = "CTRL|SHIFT",
                                                                                                                                                                                                                                                                                                            action = wezterm.action.ActivateTabRelative(-1),
                                                                                                                                                                                                                                                                                                                }},
                                                                                                                                                                                                                                                                                                                    {{
                                                                                                                                                                                                                                                                                                                          key = "RightArrow",
                                                                                                                                                                                                                                                                                                                                mods = "CTRL|SHIFT",
                                                                                                                                                                                                                                                                                                                                      action = wezterm.action.ActivateTabRelative(1),
                                                                                                                                                                                                                                                                                                                                          }},
                                                                                                                                                                                                                                                                                                                                              {{
                                                                                                                                                                                                                                                                                                                                                    key = "r",
                                                                                                                                                                                                                                                                                                                                                          mods = "CTRL|SHIFT",
                                                                                                                                                                                                                                                                                                                                                                action = wezterm.action.ReloadConfiguration,
                                                                                                                                                                                                                                                                                                                                                                    }},
                                                                                                                                                                                                                                                                                                                                                                        {{
                                                                                                                                                                                                                                                                                                                                                                              key = "h",
                                                                                                                                                                                                                                                                                                                                                                                    mods = "CTRL|SHIFT",
                                                                                                                                                                                                                                                                                                                                                                                          action = wezterm.action.SplitHorizontal({{domain = "CurrentPaneDomain"}}),
                                                                                                                                                                                                                                                                                                                                                                                              }},
                                                                                                                                                                                                                                                                                                                                                                                                  {{
                                                                                                                                                                                                                                                                                                                                                                                                        key = "v",
                                                                                                                                                                                                                                                                                                                                                                                                              mods = "CTRL|SHIFT",
                                                                                                                                                                                                                                                                                                                                                                                                                    action = wezterm.action.SplitVertical({{domain = "CurrentPaneDomain"}}),
                                                                                                                                                                                                                                                                                                                                                                                                                        }},
                                                                                                                                                                                                                                                                                                                                                                                                                          }},

                                                                                                                                                                                                                                                                                                                                                                                                                            -- Advanced Appearance
                                                                                                                                                                                                                                                                                                                                                                                                                              window_padding = {{
                                                                                                                                                                                                                                                                                                                                                                                                                                  left = 5,
                                                                                                                                                                                                                                                                                                                                                                                                                                      right = 5,
                                                                                                                                                                                                                                                                                                                                                                                                                                          top = 5,
                                                                                                                                                                                                                                                                                                                                                                                                                                              bottom = 5,
                                                                                                                                                                                                                                                                                                                                                                                                                                                }},
                                                                                                                                                                                                                                                                                                                                                                                                                                                }}
                                                                                                                                                                                                                                                                                                                                                                                                                                                    """

    # Write the configuration to the specified file
    with open(config_path, "w") as config_file:
        config_file.write(wezterm_config)

        print(
            f"Refined WezTerm configuration generated successfully at {config_path}.")


@task
def full_mvp(c):
    """
    Full MVP setup with fixes for Android Emulator and AppAgent.
    """
    print("Starting full MVP setup...")

    # Setup .env file
    setup_env(c)

    # Validate and start services
    validate_env(c)
    start_emulator(c)

    # Build and run AppAgent
    setup_appagent(c)
    run_appagent(c)

    # Validate AppAgent endpoints
    validate_appagent_endpoints(c)

    print("MVP setup complete! Access components:")
    print("- Emulator: http://localhost:6081")
    print("- AppAgent: http://localhost:5002")


@task
def resolve_conflicts(c):
    """
    Stop and remove all running containers dynamically.
    """
    result = c.run("docker ps --format '{{.Names}}'", hide=True, warn=True)
    if result.ok:
        containers = result.stdout.splitlines()
        for container in containers:
            try:
                c.run(f"docker rm -f {container}", warn=True, pty=True)
                print(f"Removed container: {container}")
            except Exception as e:
                print(f"Could not remove container: {container}. Error: {e}")
    else:
        print("No running containers found.")


@task
def setup_android_emulator(c):
    emulator_port = get_available_port()
    c.run(
        f"docker run -d -p {emulator_port}:6080 --name android-emulator budtmo/docker-android")
    print(f"Android Emulator is running on 0.0.0.0:{emulator_port}")


@task
def validate_ports(c):
    """
    Check for port conflicts on the host machine.
    """
    ports = ["5002", "6081", "8080", "5554", "5555", "4723", "8200"]
    for port in ports:
        try:
            c.run(f"netstat -tuln | grep {port}", warn=True, pty=True)
            print(f"Port {port} is in use. Consider changing it.")
        except Exception:
            print(f"Port {port} is free.")


@task
def setup_appagent(c, bind_address="0.0.0.0", appagent_port=5002):
    """
    Set up the AppAgent with external access.

    Args:
        bind_address: The address to bind the AppAgent server (default: 0.0.0.0).
        appagent_port: The AppAgent server port (default: 5002).
    """
    # Docker container and image setup
    container_name = "appagent-xo-node-admin"
    image_name = "appagent"

    # Fetch Docker credentials from the environment
    docker_username = os.getenv("DOCKER_USERNAME")
    docker_password = os.getenv("DOCKER_PASSWORD")
    docker_registry = os.getenv("DOCKER_REGISTRY")

    # Check if Docker credentials are provided
    if not all([docker_username, docker_password, docker_registry]):
        raise ValueError("Docker credentials are missing in the .env file")

    print("Setting up AppAgent...")

    # Stop and remove any existing AppAgent container
    c.run(f"docker stop {container_name} || true", warn=True)
    c.run(f"docker rm {container_name} || true", warn=True)

    # Log in to Docker registry and pull the latest AppAgent image
    c.run(
        f"docker login -u {docker_username} -p {docker_password} {docker_registry}")
    c.run(f"docker pull {docker_registry}/{image_name}:latest")

    # Start the AppAgent container
    c.run(
        f"docker run -d --name {container_name} "
        f"-p {bind_address}:{appagent_port}:5000 "
        f"{docker_registry}/{image_name}:latest",
        pty=True,
    )

    print(f"AppAgent is running on {bind_address}:{appagent_port}")
