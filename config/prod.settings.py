# Production Flask settings from Alpine infra/docker/secfixes-tracker.
# Active config for the web app / flask CLI is secfixes_tracker/application.cfg.

PACKAGE_EXCLUSIONS = [
    "alpine-base",
    "build-base",
    "bridge",
    "docs",
]

CUSTOM_REWRITERS = {
    "jenkins:*": lambda x: "jenkins",
    "golang:protobuf": lambda x: "go-protobuf",
    "boltcms:bolt": lambda x: "boltcms",
    "samsung:*": lambda x: "samsung-" + x,
    "cygwin:*": lambda x: "cygwin-" + x,
    "facebook:zstandard": lambda x: "zstd",
    "nodejs:*": lambda x: "nodejs",
    "mozilla:network_security_services": lambda x: "nss",
    "brokenlamp:slock": lambda x: "rust-slock",
    "knplabs:snappy": lambda x: "knplabs-snappy",
    "home-assistant:supervisor": lambda x: "home-assistant-supervisor",
    "edwiser:bridge": lambda x: "wordpress-edwiser-bridge",
    "adobe:*": lambda x: f"adobe-{x}",
    "foxitsoftware:*": lambda x: f"foxitsoftware-{x}",
    "ctrip:apollo": lambda x: "ctrip-apollo",
    "python:urllib3": lambda x: "py3-urllib3",
    "isaacs:tar": lambda x: "node-tar",
    "clouflare:*": lambda x: f"cloudflare-{x}",
    "apache:apache": lambda x: "apache",
    "apache:*": lambda x: f"apache-{x}",
}
