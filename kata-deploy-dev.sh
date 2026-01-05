#!/usr/bin/env bash
# Copyright (c) 2019 Intel Corporation
#
# SPDX-License-Identifier: Apache-2.0
#

set -o errexit
set -o pipefail
set -o nounset
set -o errtrace

# -----------------------------------------------------------------------------
# Extra tracing / debug logging
#
# Control knobs:
#   TRACE=true|false          (default: true)  - high-level trace logs
#   TRACE_XTRACE=true|false   (default: false) - bash xtrace (very noisy)
#   TRACE_DUMP_ENV=true|false (default: true)  - dump env/derived vars at start
# -----------------------------------------------------------------------------

TRACE="${TRACE:-true}"
TRACE_XTRACE="${TRACE_XTRACE:-true}"
TRACE_DUMP_ENV="${TRACE_DUMP_ENV:-true}"

_now_ts() {
	# RFC3339-ish, with milliseconds (best-effort). Busybox date may not support %N.
	date +"%Y-%m-%dT%H:%M:%S%z" 2>/dev/null || date
}

_trace() {
	[[ "${TRACE}" == "true" ]] || return 0
	# shellcheck disable=SC2145
	echo "TRACE: $(_now_ts) ${FUNCNAME[1]:-main}: $*" >&2
}

_dbg_kv() {
	[[ "${TRACE}" == "true" ]] || return 0
	local k="$1"
	local v="${2-<unset>}"
	echo "TRACE: $(_now_ts) ${FUNCNAME[1]:-main}:   ${k}='${v}'" >&2
}

_enter() {
	[[ "${TRACE}" == "true" ]] || return 0
	# shellcheck disable=SC2145
	echo "TRACE: $(_now_ts) -> ENTER ${FUNCNAME[1]:-main}($*)" >&2
}

_leave() {
	[[ "${TRACE}" == "true" ]] || return 0
	echo "TRACE: $(_now_ts) <- LEAVE ${FUNCNAME[1]:-main}" >&2
}

_on_err() {
	local exit_code="$?"
	local line_no="${1:-?}"
	local cmd="${2-<unknown>}"
	echo "ERROR: $(_now_ts) Script failed (exit=${exit_code}) at line ${line_no}: ${cmd}" >&2
	echo "ERROR: Call stack:" >&2
	local i=0
	# FUNCNAME[0] is _on_err, skip it
	for ((i=1; i<${#FUNCNAME[@]}; i++)); do
		echo "ERROR:   #$((i-1)) ${FUNCNAME[$i]} (line ${BASH_LINENO[$((i-1))]:-?})" >&2
	done
	exit "${exit_code}"
}

trap '_on_err "${LINENO}" "${BASH_COMMAND}"' ERR

if [[ "${TRACE_XTRACE}" == "true" ]]; then
	# Extremely noisy, but perfect for “what path did bash take?”
	# PS4 shows time + file:line + function name.
	export PS4='+ $(_now_ts) ${BASH_SOURCE##*/}:${LINENO} ${FUNCNAME[0]:-main}(): '
	set -x
fi

crio_drop_in_conf_dir="/etc/crio/crio.conf.d/"
crio_drop_in_conf_file="${crio_drop_in_conf_dir}/99-kata-deploy"
crio_drop_in_conf_file_debug="${crio_drop_in_conf_dir}/100-debug"
containerd_conf_file="/etc/containerd/config.toml"
containerd_conf_file_backup="${containerd_conf_file}.bak"
containerd_conf_tmpl_file=""
use_containerd_drop_in_conf_file="false"

# Backups are intentionally disabled (do not create .bak files).
create_containerd_conf_backup="false"

# If we fail for any reason a message will be displayed
die() {
	_enter "$@"
	msg="$*"
	echo "ERROR: $msg" >&2
	_leave
	exit 1
}

warn() {
	_enter "$@"
	msg="$*"
	echo "WARN: $msg" >&2
	_leave
}

info() {
	_enter "$@"
	msg="$*"
	echo "INFO: $msg" >&2
	_leave
}

# Get existing values from a TOML array field and return them as a comma-separated string
# * get_field_array_values "${config}" "enable_annotations" "${shim}"
get_field_array_values() {
	_enter "$@"
	local config_file="$1"
	local field="$2"
	local shim="${3:-}"

	_dbg_kv "config_file" "${config_file}"
	_dbg_kv "field" "${field}"
	_dbg_kv "shim" "${shim}"

	# Determine hypervisor name if shim is provided
	local hypervisor_name=""
	if [[ -n "${shim}" ]]; then
		_trace "shim provided -> resolving hypervisor_name via get_hypervisor_name"
		hypervisor_name=$(get_hypervisor_name "${shim}")
	fi
	_dbg_kv "hypervisor_name" "${hypervisor_name}"

	# Get array values using tomlq - output each element on a new line, then convert to comma-separated
	local array_values=""
	if [[ -n "${hypervisor_name}" ]]; then
		_trace "trying hypervisor-scoped array: .hypervisor.${hypervisor_name}.${field}"
		array_values=$(tomlq -r '.hypervisor.'"${hypervisor_name}"'.'"${field}"' // [] | .[]' "${config_file}" 2>/dev/null || echo "")
	fi

	# Fallback: try without hypervisor prefix (for top-level fields)
	if [[ -z "${array_values}" ]] || [[ "${array_values}" == "null" ]]; then
		_trace "fallback to top-level array: .${field}"
		array_values=$(tomlq -r '."'"${field}"'" // [] | .[]' "${config_file}" 2>/dev/null || echo "")
	fi

	_dbg_kv "array_values_raw" "${array_values}"

	# Convert newline-separated values to comma-separated string
	if [[ -n "${array_values}" ]]; then
		local out
		out="$(echo "${array_values}" | tr '\n' ',' | sed 's/,$//')"
		_dbg_kv "array_values_csv" "${out}"
		echo "${out}"
	else
		echo ""
	fi
	_leave
}

# Returns success if the file looks like a Go template (contains '{{ ... }}'),
# which tomlq cannot safely parse.
is_go_template_file() {
	_enter "$@"
	local f="$1"
	_dbg_kv "file" "${f}"

	[[ -f "$f" ]] || { _trace "file does not exist -> not a go template"; _leave; return 1; }
	if grep -q '{{' "$f"; then
		_trace "detected '{{' -> looks like go template"
		_leave
		return 0
	fi

	_trace "no '{{' found -> not a go template"
	_leave
	return 1
}

# Ensure containerd 'imports' contains the Kata drop-in file and does not include
# non-*.toml entries under the Kata containerd directory (avoids *.toml.tmpl, dirs, globs like '*').
# This keeps any non-Kata imports intact.
ensure_containerd_imports() {
	_enter "$@"
	local conf_file="$1"
	local kata_containerd_prefix="$2" # e.g. /opt/kata/containerd/
	local import_path="$3"            # e.g. /opt/kata/containerd/config.d/kata-deploy.toml

	_dbg_kv "conf_file" "${conf_file}"
	_dbg_kv "kata_containerd_prefix" "${kata_containerd_prefix}"
	_dbg_kv "import_path" "${import_path}"

	[[ -f "$conf_file" ]] || { _trace "conf_file missing -> nothing to do"; _leave; return 0; }

	# Don't try to parse Go templates as TOML.
	if is_go_template_file "$conf_file"; then
		warn "Skipping TOML edit for Go template file: ${conf_file}"
		_leave
		return 0
	fi

	local expr
	expr=$(printf '.imports = ((.imports // []) | map(select((startswith("%s")|not) or endswith(".toml"))) + ["%s"] | unique)' \
		"${kata_containerd_prefix}" "${import_path}")
	_dbg_kv "tomlq_expr" "${expr}"

	_trace "running tomlq to ensure imports contain drop-in and exclude non-*.toml under kata prefix"
	tomlq -i -t "${expr}" "${conf_file}" 2>/dev/null || true
	_leave
}

# Remove a specific import from containerd config (safe for missing field).
remove_containerd_import() {
	_enter "$@"
	local conf_file="$1"
	local import_path="$2"

	_dbg_kv "conf_file" "${conf_file}"
	_dbg_kv "import_path" "${import_path}"

	[[ -f "$conf_file" ]] || { _trace "conf_file missing -> nothing to do"; _leave; return 0; }

	# Don't try to parse Go templates as TOML.
	if is_go_template_file "$conf_file"; then
		warn "Skipping TOML edit for Go template file: ${conf_file}"
		_leave
		return 0
	fi

	local expr
	expr=$(printf '.imports |= ((. // []) | map(select(. != "%s")))' "${import_path}")
	_dbg_kv "tomlq_expr" "${expr}"

	_trace "running tomlq to remove import"
	tomlq -i -t "${expr}" "${conf_file}" 2>/dev/null || true
	_leave
}

# Write the requested Go template snippet to /etc/containerd/kata.toml.tmpl:
# {{ template "base" . }}
# imports = ["..."]
#
# import_path must be provided by caller.
write_containerd_kata_template() {
	_enter "$@"
	local import_path="$1"
	local tmpl_file="/etc/containerd/kata.toml.tmpl"

	_dbg_kv "tmpl_file" "${tmpl_file}"
	_dbg_kv "import_path" "${import_path}"

	mkdir -p "$(dirname "$tmpl_file")"
	cat >"${tmpl_file}" <<EOF
{{ template "base" . }}
imports = ["${import_path}"]
EOF
	_trace "wrote ${tmpl_file}"
	_leave
}

DEBUG="${DEBUG:-"false"}"

ARCH=$(uname -m)
_trace "detected ARCH=$(uname -m)"

SHIMS_X86_64="${SHIMS_X86_64:-"clh cloud-hypervisor dragonball fc qemu qemu-coco-dev qemu-coco-dev-runtime-rs qemu-runtime-rs qemu-snp qemu-tdx qemu-nvidia-gpu qemu-nvidia-gpu-snp qemu-nvidia-gpu-tdx"}"
SHIMS_AARCH64="${SHIMS_AARCH64:-"clh cloud-hypervisor dragonball fc qemu qemu-nvidia-gpu qemu-cca"}"
SHIMS_S390X="${SHIMS_S390X:-"qemu qemu-runtime-rs qemu-se qemu-se-runtime-rs qemu-coco-dev qemu-coco-dev-runtime-rs"}"
SHIMS_PPC64LE="${SHIMS_PPC64LE:-"qemu"}"

DEFAULT_SHIM_X86_64="${DEFAULT_SHIM_X86_64:-"qemu"}"
DEFAULT_SHIM_AARCH64="${DEFAULT_SHIM_AARCH64:-"qemu"}"
DEFAULT_SHIM_S390X="${DEFAULT_SHIM_S390X:-"qemu"}"
DEFAULT_SHIM_PPC64LE="${DEFAULT_SHIM_PPC64LE:-"qemu"}"

SNAPSHOTTER_HANDLER_MAPPING_X86_64="${SNAPSHOTTER_HANDLER_MAPPING_X86_64:-}"
SNAPSHOTTER_HANDLER_MAPPING_AARCH64="${SNAPSHOTTER_HANDLER_MAPPING_AARCH64:-}"
SNAPSHOTTER_HANDLER_MAPPING_S390X="${SNAPSHOTTER_HANDLER_MAPPING_S390X:-}"
SNAPSHOTTER_HANDLER_MAPPING_PPC64LE="${SNAPSHOTTER_HANDLER_MAPPING_PPC64LE:-}"

ALLOWED_HYPERVISOR_ANNOTATIONS_X86_64="${ALLOWED_HYPERVISOR_ANNOTATIONS_X86_64:-}"
ALLOWED_HYPERVISOR_ANNOTATIONS_AARCH64="${ALLOWED_HYPERVISOR_ANNOTATIONS_AARCH64:-}"
ALLOWED_HYPERVISOR_ANNOTATIONS_S390X="${ALLOWED_HYPERVISOR_ANNOTATIONS_S390X:-}"
ALLOWED_HYPERVISOR_ANNOTATIONS_PPC64LE="${ALLOWED_HYPERVISOR_ANNOTATIONS_PPC64LE:-}"

PULL_TYPE_MAPPING_X86_64="${PULL_TYPE_MAPPING_X86_64:-}"
PULL_TYPE_MAPPING_AARCH64="${PULL_TYPE_MAPPING_AARCH64:-}"
PULL_TYPE_MAPPING_S390X="${PULL_TYPE_MAPPING_S390X:-}"
PULL_TYPE_MAPPING_PPC64LE="${PULL_TYPE_MAPPING_PPC64LE:-}"

EXPERIMENTAL_FORCE_GUEST_PULL_X86_64="${EXPERIMENTAL_FORCE_GUEST_PULL_X86_64:-}"
EXPERIMENTAL_FORCE_GUEST_PULL_AARCH64="${EXPERIMENTAL_FORCE_GUEST_PULL_AARCH64:-}"
EXPERIMENTAL_FORCE_GUEST_PULL_S390X="${EXPERIMENTAL_FORCE_GUEST_PULL_S390X:-}"
EXPERIMENTAL_FORCE_GUEST_PULL_PPC64LE="${EXPERIMENTAL_FORCE_GUEST_PULL_PPC64LE:-}"

SHIMS_FOR_ARCH=""
DEFAULT_SHIM_FOR_ARCH=""
SNAPSHOTTER_HANDLER_MAPPING_FOR_ARCH=""
ALLOWED_HYPERVISOR_ANNOTATIONS_FOR_ARCH=""
PULL_TYPE_MAPPING_FOR_ARCH=""
EXPERIMENTAL_FORCE_GUEST_PULL_FOR_ARCH=""

_trace "selecting arch-specific variables (case ${ARCH})"
case ${ARCH} in
	x86_64)
		SHIMS_FOR_ARCH="${SHIMS_X86_64}"
		DEFAULT_SHIM_FOR_ARCH="${DEFAULT_SHIM_X86_64}"
		SNAPSHOTTER_HANDLER_MAPPING_FOR_ARCH="${SNAPSHOTTER_HANDLER_MAPPING_X86_64}"
		ALLOWED_HYPERVISOR_ANNOTATIONS_FOR_ARCH="${ALLOWED_HYPERVISOR_ANNOTATIONS_X86_64}"
		PULL_TYPE_MAPPING_FOR_ARCH="${PULL_TYPE_MAPPING_X86_64}"
		EXPERIMENTAL_FORCE_GUEST_PULL_FOR_ARCH="${EXPERIMENTAL_FORCE_GUEST_PULL_X86_64}"
		;;
	aarch64)
		SHIMS_FOR_ARCH="${SHIMS_AARCH64}"
		DEFAULT_SHIM_FOR_ARCH="${DEFAULT_SHIM_AARCH64}"
		SNAPSHOTTER_HANDLER_MAPPING_FOR_ARCH="${SNAPSHOTTER_HANDLER_MAPPING_AARCH64}"
		ALLOWED_HYPERVISOR_ANNOTATIONS_FOR_ARCH="${ALLOWED_HYPERVISOR_ANNOTATIONS_AARCH64}"
		PULL_TYPE_MAPPING_FOR_ARCH="${PULL_TYPE_MAPPING_AARCH64}"
		EXPERIMENTAL_FORCE_GUEST_PULL_FOR_ARCH="${EXPERIMENTAL_FORCE_GUEST_PULL_AARCH64}"
		;;
	s390x)
		SHIMS_FOR_ARCH="${SHIMS_S390X}"
		DEFAULT_SHIM_FOR_ARCH="${DEFAULT_SHIM_S390X}"
		SNAPSHOTTER_HANDLER_MAPPING_FOR_ARCH="${SNAPSHOTTER_HANDLER_MAPPING_S390X}"
		ALLOWED_HYPERVISOR_ANNOTATIONS_FOR_ARCH="${ALLOWED_HYPERVISOR_ANNOTATIONS_S390X}"
		PULL_TYPE_MAPPING_FOR_ARCH="${PULL_TYPE_MAPPING_S390X}"
		EXPERIMENTAL_FORCE_GUEST_PULL_FOR_ARCH="${EXPERIMENTAL_FORCE_GUEST_PULL_S390X}"
		;;
	ppc64le)
		SHIMS_FOR_ARCH="${SHIMS_PPC64LE}"
		DEFAULT_SHIM_FOR_ARCH="${DEFAULT_SHIM_PPC64LE}"
		SNAPSHOTTER_HANDLER_MAPPING_FOR_ARCH="${SNAPSHOTTER_HANDLER_MAPPING_PPC64LE}"
		ALLOWED_HYPERVISOR_ANNOTATIONS_FOR_ARCH="${ALLOWED_HYPERVISOR_ANNOTATIONS_PPC64LE}"
		PULL_TYPE_MAPPING_FOR_ARCH="${PULL_TYPE_MAPPING_PPC64LE}"
		EXPERIMENTAL_FORCE_GUEST_PULL_FOR_ARCH="${EXPERIMENTAL_FORCE_GUEST_PULL_PPC64LE}"
		;;
	*)
		die "Unsupported architecture: ${ARCH}"
		;;
esac

IFS=' ' read -a shims <<< "${SHIMS_FOR_ARCH}"
default_shim="${DEFAULT_SHIM_FOR_ARCH}"

IFS=',' read -a snapshotters <<< "${SNAPSHOTTER_HANDLER_MAPPING_FOR_ARCH}"
snapshotters_delimiter=':'

IFS=' ' read -a hypervisor_annotations <<< "${ALLOWED_HYPERVISOR_ANNOTATIONS_FOR_ARCH}"

IFS=',' read -a pull_types <<< "${PULL_TYPE_MAPPING_FOR_ARCH}"

IFS="," read -a experimental_force_guest_pull <<< "${EXPERIMENTAL_FORCE_GUEST_PULL_FOR_ARCH}"

AGENT_HTTPS_PROXY="${AGENT_HTTPS_PROXY:-}"
AGENT_NO_PROXY="${AGENT_NO_PROXY:-}"

EXPERIMENTAL_SETUP_SNAPSHOTTER="${EXPERIMENTAL_SETUP_SNAPSHOTTER:-}"
IFS=',' read -a experimental_setup_snapshotter <<< "${EXPERIMENTAL_SETUP_SNAPSHOTTER}"

INSTALLATION_PREFIX="${INSTALLATION_PREFIX:-}"
default_dest_dir="/opt/kata"
dest_dir="${default_dest_dir}"
if [ -n "${INSTALLATION_PREFIX}" ]; then
	_trace "INSTALLATION_PREFIX set -> validating and computing dest_dir"
	if [[ "${INSTALLATION_PREFIX:0:1}" != "/" ]]; then
		die 'INSTALLATION_PREFIX must begin with a "/"(ex. /hoge/fuga)'
	fi
	# There's no `/` in between ${INSTALLATION_PREFIX} and ${default_dest_dir}
	# as, otherwise, we'd have it doubled there, as: `/foo/bar//opt/kata`
	dest_dir="${INSTALLATION_PREFIX}${default_dest_dir}"
fi

MULTI_INSTALL_SUFFIX="${MULTI_INSTALL_SUFFIX:-}"
if [ -n "${MULTI_INSTALL_SUFFIX}" ]; then
	_trace "MULTI_INSTALL_SUFFIX set -> adjusting dest_dir and crio_drop_in_conf_file"
	dest_dir="${dest_dir}-${MULTI_INSTALL_SUFFIX}"
	crio_drop_in_conf_file="${crio_drop_in_conf_file}-${MULTI_INSTALL_SUFFIX}"
fi
containerd_drop_in_conf_file="${dest_dir}/containerd/config.d/kata-deploy.toml"

# Here, again, there's no `/` between /host and ${dest_dir}, otherwise we'd have it
# doubled here as well, as: `/host//opt/kata`
host_install_dir="/host${dest_dir}"

HELM_POST_DELETE_HOOK="${HELM_POST_DELETE_HOOK:-"false"}"

function host_systemctl() {
	_enter "$@"
	_trace "nsenter systemctl $*"
	nsenter --target 1 --mount systemctl "${@}"
	_leave
}

function host_exec() {
	_enter "$@"
	_trace "nsenter bash -c $*"
	nsenter --target 1 --mount bash -c "$*"
	_leave
}

function print_usage() {
	_enter
	echo "Usage: $0 [install/cleanup/reset]"
	_leave
}

function patch_runtimeclasses_for_nfd() {
	_enter
	info "Patching existing runtime classes for NFD"

	for shim in "${shims[@]}"; do
		_trace "shim loop: ${shim}"
		local runtime_class_name="kata-${shim}"
		if [[ -n "${MULTI_INSTALL_SUFFIX}" ]]; then
			runtime_class_name="kata-${shim}-${MULTI_INSTALL_SUFFIX}"
		fi
		_dbg_kv "runtime_class_name" "${runtime_class_name}"

		# Check if runtime class exists
		if ! kubectl get runtimeclass "${runtime_class_name}" &>/dev/null; then
			_trace "runtimeclass ${runtime_class_name} not found -> continue"
			continue
		fi
		_trace "runtimeclass ${runtime_class_name} exists"

		case "${shim}" in
			*tdx*)
				info "Patching runtime class ${runtime_class_name} for TDX NFD support"
				kubectl patch runtimeclass "${runtime_class_name}" --type=merge \
					-p='{"overhead":{"podFixed":{"tdx.intel.com/keys":1}}}'
				;;
			*snp*)
				info "Patching runtime class ${runtime_class_name} for SNP NFD support"
				kubectl patch runtimeclass "${runtime_class_name}" --type=merge \
					-p='{"overhead":{"podFixed":{"sev-snp.amd.com/esids":1}}}'
				;;
			*)
				_trace "shim ${shim} -> no NFD patch case"
				;;
		esac
	done
	_leave
}

function get_container_runtime() {
	_enter
	_dbg_kv "NODE_NAME" "${NODE_NAME-<unset>}"

	local runtime
	runtime=$(kubectl get node $NODE_NAME -o jsonpath='{.status.nodeInfo.containerRuntimeVersion}')
	local microk8s
	microk8s=$(kubectl get node $NODE_NAME -o jsonpath='{.metadata.labels.microk8s\.io\/cluster}')
	_dbg_kv "nodeInfo.containerRuntimeVersion" "${runtime}"
	_dbg_kv "microk8s label" "${microk8s}"

	if [ "$?" -ne 0 ]; then
		die "invalid node name"
	fi

	if echo "$runtime" | grep -qE "cri-o"; then
		_trace "detected cri-o"
		echo "cri-o"
	elif [ "$microk8s" == "true" ]; then
		_trace "detected microk8s label"
		echo "microk8s"
	elif echo "$runtime" | grep -qE 'containerd.*-k3s'; then
		_trace "detected k3s-style containerd"
		if host_systemctl is-active --quiet rke2-agent; then
			_trace "rke2-agent active"
			echo "rke2-agent"
		elif host_systemctl is-active --quiet rke2-server; then
			_trace "rke2-server active"
			echo "rke2-server"
		elif host_systemctl is-active --quiet k3s-agent; then
			_trace "k3s-agent active"
			echo "k3s-agent"
		else
			_trace "defaulting to k3s"
			echo "k3s"
		fi
	elif host_systemctl is-active --quiet k0scontroller; then
		_trace "k0scontroller active"
		echo "k0s-controller"
	elif host_systemctl is-active --quiet k0sworker; then
		_trace "k0sworker active"
		echo "k0s-worker"
	else
		_trace "defaulting to prefix before ':' of containerRuntimeVersion"
		echo "$runtime" | awk -F '[:]' '{print $1}'
	fi
	_leave
}

function is_containerd_capable_of_using_drop_in_files() {
	_enter "$@"
	local runtime="$1"
	_dbg_kv "runtime" "${runtime}"

	if [ "$runtime" == "crio" ]; then
		_trace "runtime=crio -> false"
		echo "false"
		_leave
		return
	fi

	if [[ "$runtime" =~ ^(k0s-worker|k0s-controller)$ ]]; then
		_trace "runtime=k0s* -> false"
		echo "false"
		_leave
		return
	fi

	if [ "$runtime" == "microk8s" ]; then
		_trace "runtime=microk8s -> false"
		echo "false"
		_leave
		return
	fi

	local version_major
	version_major=$(kubectl get node $NODE_NAME -o jsonpath='{.status.nodeInfo.containerRuntimeVersion}' | grep -oE '[0-9]+\.[0-9]+' | cut -d'.' -f1)
	_dbg_kv "containerd_version_major" "${version_major}"

	if [ $version_major -lt 2 ]; then
		_trace "containerd major < 2 -> false"
		echo "false"
		_leave
		return
	fi

	_trace "containerd major >= 2 -> true"
	echo "true"
	_leave
}

function get_kata_containers_config_path() {
	_enter "$@"
	local shim="$1"
	_dbg_kv "shim" "${shim}"

	local golang_config_path="${dest_dir}/share/defaults/kata-containers"
	local rust_config_path="${golang_config_path}/runtime-rs"
	local config_path

	case "$shim" in
		cloud-hypervisor | dragonball | qemu-runtime-rs | qemu-coco-dev-runtime-rs | qemu-se-runtime-rs)
			config_path="$rust_config_path"
			_trace "shim maps to rust runtime config path"
			;;
		*)
			config_path="$golang_config_path"
			_trace "shim maps to golang runtime config path"
			;;
	esac

	_dbg_kv "config_path" "${config_path}"
	echo "$config_path"
	_leave
}

function get_kata_containers_runtime_path() {
	_enter "$@"
	local shim="$1"
	_dbg_kv "shim" "${shim}"

	local runtime_path
	case "$shim" in
		cloud-hypervisor | dragonball | qemu-runtime-rs | qemu-coco-dev-runtime-rs | qemu-se-runtime-rs)
			runtime_path="${dest_dir}/runtime-rs/bin/containerd-shim-kata-v2"
			_trace "shim maps to runtime-rs shim"
			;;
		*)
			runtime_path="${dest_dir}/bin/containerd-shim-kata-v2"
			_trace "shim maps to golang shim"
			;;
	esac

	_dbg_kv "runtime_path" "${runtime_path}"
	echo "$runtime_path"
	_leave
}

function tdx_not_supported() {
	_enter "$@"
	distro="${1}"
	version="${2}"
	warn "Distro ${distro} ${version} does not support TDX and the TDX related runtime classes will not work in your cluster!"
	_leave
}

function tdx_supported() {
	_enter "$@"
	distro="${1}"
	version="${2}"
	config="${3}"

	_dbg_kv "distro" "${distro}"
	_dbg_kv "version" "${version}"
	_dbg_kv "config" "${config}"

	local qemu_path
	qemu_path=$(get_tdx_qemu_path_from_distro ${distro})
	local ovmf_path
	ovmf_path=$(get_tdx_ovmf_path_from_distro ${distro})

	_dbg_kv "qemu_path" "${qemu_path}"
	_dbg_kv "ovmf_path" "${ovmf_path}"

	tomlq -i -t '.hypervisor.qemu.path = "'"${qemu_path}"'"' "${config}" 2>/dev/null || true
	tomlq -i -t '.hypervisor.qemu.firmware = "'"${ovmf_path}"'"' "${config}" 2>/dev/null || true

	info "In order to use the tdx related runtime classes, ensure TDX is properly configured for ${distro} ${version} by following the instructions provided at: $(get_tdx_distro_instructions ${distro})"
	_leave
}

function get_tdx_distro_instructions() {
	_enter "$@"
	distro="${1}"
	case ${distro} in
		ubuntu) echo "https://github.com/canonical/tdx/tree/3.3" ;;
		centos) echo "https://sigs.centos.org/virt/tdx" ;;
	esac
	_leave
}

function get_tdx_qemu_path_from_distro() {
	_enter "$@"
	distro="${1}"
	case ${distro} in
		ubuntu) echo "/usr/bin/qemu-system-x86_64" ;;
		centos) echo "/usr/libexec/qemu-kvm" ;;
	esac
	_leave
}

function get_tdx_ovmf_path_from_distro() {
	_enter "$@"
	distro="${1}"
	case ${distro} in
		ubuntu) echo "/usr/share/ovmf/OVMF.fd" ;;
		centos) echo "/usr/share/edk2/ovmf/OVMF.inteltdx.fd" ;;
	esac
	_leave
}

function adjust_qemu_cmdline() {
	_enter "$@"
	shim="${1}"
	config_path="${2}"
	qemu_share="${shim}"

	_dbg_kv "shim" "${shim}"
	_dbg_kv "config_path" "${config_path}"

	[[ "${shim}" == "qemu-nvidia-gpu-snp" ]] && qemu_share=qemu-snp-experimental
	[[ "${shim}" == "qemu-nvidia-gpu-tdx" ]] && qemu_share=qemu-tdx-experimental
	[[ "${shim}" == "qemu-cca" ]] && qemu_share=qemu-cca-experimental

	[[ "${shim}" =~ ^(qemu|qemu-runtime-rs|qemu-snp|qemu-se|qemu-se-runtime-rs|qemu-coco-dev|qemu-coco-dev-runtime-rs|qemu-nvidia-gpu)$ ]] && qemu_share="qemu"
	_dbg_kv "qemu_share" "${qemu_share}"

	qemu_binary=$(tomlq '.hypervisor.qemu.path' ${config_path} | tr -d \")
	qemu_binary_script="${qemu_binary}-installation-prefix"
	qemu_binary_script_host_path="/host/${qemu_binary_script}"

	_dbg_kv "qemu_binary" "${qemu_binary}"
	_dbg_kv "qemu_binary_script" "${qemu_binary_script}"
	_dbg_kv "qemu_binary_script_host_path" "${qemu_binary_script_host_path}"

	if [[ ! -f ${qemu_binary_script_host_path} ]]; then
		_trace "creating qemu wrapper script: ${qemu_binary_script_host_path}"
		cat <<EOF >${qemu_binary_script_host_path}
#!/usr/bin/env bash

exec ${qemu_binary} "\$@" -L ${dest_dir}/share/kata-${qemu_share}/qemu/
EOF
		chmod +x ${qemu_binary_script_host_path}
	else
		_trace "qemu wrapper script already exists"
	fi

	_trace "updating .hypervisor.qemu.path to wrapper: ${qemu_binary_script}"
	tomlq -i -t '.hypervisor.qemu.path = "'"${qemu_binary_script}"'"' "${config_path}" 2>/dev/null || true
	_leave
}

function get_hypervisor_name() {
	_enter "$@"
	local shim="${1}"
	_dbg_kv "shim" "${shim}"

	case "${shim}" in
		qemu-runtime-rs | qemu-coco-dev-runtime-rs | qemu-se-runtime-rs | qemu | qemu-tdx | qemu-snp | qemu-se | qemu-coco-dev | qemu-cca | qemu-nvidia-gpu | qemu-nvidia-gpu-tdx | qemu-nvidia-gpu-snp)
			echo "qemu"
			;;
		clh) echo "clh" ;;
		cloud-hypervisor) echo "cloud-hypervisor" ;;
		dragonball) echo "dragonball" ;;
		fc | firecracker) echo "firecracker" ;;
		stratovirt) echo "stratovirt" ;;
		remote) echo "remote" ;;
		*)
			echo "${shim}"
			;;
	esac
	_leave
}

function install_artifacts() {
	_enter
	echo "copying kata artifacts onto host"
	_dbg_kv "host_install_dir" "${host_install_dir}"
	_dbg_kv "dest_dir" "${dest_dir}"

	mkdir -p ${host_install_dir}
	cp -au /opt/kata-artifacts/opt/kata/* ${host_install_dir}/
	chmod +x ${host_install_dir}/bin/*
	[ -d ${host_install_dir}/runtime-rs/bin ] && chmod +x ${host_install_dir}/runtime-rs/bin/*

	local config_path

	for shim in "${shims[@]}"; do
		_trace "install_artifacts shim loop: ${shim}"
		config_path="/host/$(get_kata_containers_config_path "${shim}")"
		_dbg_kv "config_path" "${config_path}"
		mkdir -p "$config_path"

		local kata_config_file="${config_path}/configuration-${shim}.toml"
		_dbg_kv "kata_config_file" "${kata_config_file}"

		if [ -n "${AGENT_HTTPS_PROXY}" ]; then
			_trace "AGENT_HTTPS_PROXY set -> applying proxy kernel params logic"
			local https_proxy_value=""

			if [[ "${AGENT_HTTPS_PROXY}" == *=* ]]; then
				_trace "AGENT_HTTPS_PROXY per-shim format detected"
				IFS=';' read -ra proxy_mappings <<< "${AGENT_HTTPS_PROXY}"
				for mapping in "${proxy_mappings[@]}"; do
					local key="${mapping%%=*}"
					local value="${mapping#*=}"
					_trace "proxy mapping: key=${key} value=${value}"
					if [[ "${key}" == "${shim}" ]]; then
						https_proxy_value="${value}"
						break
					fi
				done
			else
				_trace "AGENT_HTTPS_PROXY global format detected"
				https_proxy_value="${AGENT_HTTPS_PROXY}"
			fi

			_dbg_kv "https_proxy_value" "${https_proxy_value}"

			if [[ -n "${https_proxy_value}" ]]; then
				local hypervisor_name
				hypervisor_name=$(get_hypervisor_name "${shim}")
				local current_params
				current_params=$(tomlq -r '.hypervisor.'"${hypervisor_name}"'.kernel_params // ""' "${kata_config_file}" 2>/dev/null || echo "")
				_dbg_kv "current_params" "${current_params}"
				if [[ "${current_params}" != *"agent.https_proxy"* ]]; then
					local new_params="${current_params}"
					[[ -n "${new_params}" ]] && new_params+=" "
					new_params+="agent.https_proxy=${https_proxy_value}"
					_dbg_kv "new_params" "${new_params}"
					tomlq -i -t '.hypervisor.'"${hypervisor_name}"'.kernel_params = "'"${new_params}"'"' "${kata_config_file}" 2>/dev/null || true
				else
					_trace "agent.https_proxy already present -> skipping"
				fi
			fi
		fi

		if [ -n "${AGENT_NO_PROXY}" ]; then
			_trace "AGENT_NO_PROXY set -> applying no_proxy kernel params logic"
			local no_proxy_value=""

			if [[ "${AGENT_NO_PROXY}" == *=* ]]; then
				_trace "AGENT_NO_PROXY per-shim format detected"
				IFS=';' read -ra noproxy_mappings <<< "${AGENT_NO_PROXY}"
				for mapping in "${noproxy_mappings[@]}"; do
					local key="${mapping%%=*}"
					local value="${mapping#*=}"
					_trace "no_proxy mapping: key=${key} value=${value}"
					if [[ "${key}" == "${shim}" ]]; then
						no_proxy_value="${value}"
						break
					fi
				done
			else
				_trace "AGENT_NO_PROXY global format detected"
				no_proxy_value="${AGENT_NO_PROXY}"
			fi

			_dbg_kv "no_proxy_value" "${no_proxy_value}"

			if [[ -n "${no_proxy_value}" ]]; then
				local hypervisor_name
				hypervisor_name=$(get_hypervisor_name "${shim}")
				local current_params
				current_params=$(tomlq -r '.hypervisor.'"${hypervisor_name}"'.kernel_params // ""' "${kata_config_file}" 2>/dev/null || echo "")
				_dbg_kv "current_params" "${current_params}"
				if [[ "${current_params}" != *"agent.no_proxy"* ]]; then
					local new_params="${current_params}"
					[[ -n "${new_params}" ]] && new_params+=" "
					new_params+="agent.no_proxy=${no_proxy_value}"
					_dbg_kv "new_params" "${new_params}"
					tomlq -i -t '.hypervisor.'"${hypervisor_name}"'.kernel_params = "'"${new_params}"'"' "${kata_config_file}" 2>/dev/null || true
				else
					_trace "agent.no_proxy already present -> skipping"
				fi
			fi
		fi

		if [[ "${DEBUG}" == "true" ]]; then
			_trace "DEBUG=true -> enabling kata debug knobs"
			local hypervisor_name
			hypervisor_name=$(get_hypervisor_name "${shim}")

			local current_enable_debug
			current_enable_debug=$(tomlq -r '.hypervisor.'"${hypervisor_name}"'.enable_debug // false' "${kata_config_file}" 2>/dev/null || echo "false")
			_dbg_kv "current_enable_debug" "${current_enable_debug}"
			if [[ "${current_enable_debug}" != "true" ]]; then
				tomlq -i -t '.hypervisor.'"${hypervisor_name}"'.enable_debug = true' "${kata_config_file}" 2>/dev/null || true
			fi

			local current_runtime_debug
			current_runtime_debug=$(tomlq -r '.runtime.enable_debug // false' "${kata_config_file}" 2>/dev/null || echo "false")
			_dbg_kv "current_runtime_debug" "${current_runtime_debug}"
			if [[ "${current_runtime_debug}" != "true" ]]; then
				tomlq -i -t '.runtime.enable_debug = true' "${kata_config_file}" 2>/dev/null || true
			fi

			local current_debug_console
			current_debug_console=$(tomlq -r '.agent.kata.debug_console_enabled // false' "${kata_config_file}" 2>/dev/null || echo "false")
			_dbg_kv "current_debug_console" "${current_debug_console}"
			if [[ "${current_debug_console}" != "true" ]]; then
				tomlq -i -t '.agent.kata.debug_console_enabled = true' "${kata_config_file}" 2>/dev/null || true
			fi

			local current_agent_debug
			current_agent_debug=$(tomlq -r '.agent.kata.enable_debug // false' "${kata_config_file}" 2>/dev/null || echo "false")
			_dbg_kv "current_agent_debug" "${current_agent_debug}"
			if [[ "${current_agent_debug}" != "true" ]]; then
				tomlq -i -t '.agent.kata.enable_debug = true' "${kata_config_file}" 2>/dev/null || true
			fi

			local current_params
			current_params=$(tomlq -r '.hypervisor.'"${hypervisor_name}"'.kernel_params // ""' "${kata_config_file}" 2>/dev/null || echo "")
			_dbg_kv "current_params" "${current_params}"

			local debug_params=""
			if [[ "${current_params}" != *"agent.log=debug"* ]]; then
				debug_params+=" agent.log=debug"
			fi
			if [[ "${current_params}" != *"initcall_debug"* ]]; then
				debug_params+=" initcall_debug"
			fi
			_dbg_kv "debug_params_to_add" "${debug_params}"

			if [[ -n "${debug_params}" ]]; then
				local new_params="${current_params}${debug_params}"
				_dbg_kv "new_params" "${new_params}"
				tomlq -i -t '.hypervisor.'"${hypervisor_name}"'.kernel_params = "'"${new_params}"'"' "${kata_config_file}" 2>/dev/null || true
			fi
		else
			_trace "DEBUG!=true -> skipping kata debug knobs"
		fi

		if [[ ${#hypervisor_annotations[@]} -gt 0 ]]; then
			_trace "hypervisor_annotations present -> applying enable_annotations merge/dedupe"
			local shim_specific_annotations=""
			local global_annotations=""

			for m in "${hypervisor_annotations[@]}"; do
				if [[ "${m}" == *:* ]]; then
					local key="${m%:*}"
					local value="${m#*:}"
					_trace "annotation mapping shim-specific: key=${key} value=${value}"
					if [[ "${key}" != "${shim}" ]]; then
						continue
					fi
					[[ -n "${shim_specific_annotations}" ]] && shim_specific_annotations+=","
					shim_specific_annotations+="${value}"
				else
					_trace "annotation mapping global: ${m}"
					[[ -n "${global_annotations}" ]] && global_annotations+=","
					global_annotations+="$(echo "${m}" | sed 's/ /,/g')"
				fi
			done

			local all_annotations="${global_annotations}"
			if [[ -n "${shim_specific_annotations}" ]]; then
				[[ -n "${all_annotations}" ]] && all_annotations+=","
				all_annotations+="${shim_specific_annotations}"
			fi

			_dbg_kv "all_annotations" "${all_annotations}"

			if [[ -n "${all_annotations}" ]]; then
				local hypervisor_name
				hypervisor_name=$(get_hypervisor_name "${shim}")
				local existing_annotations
				existing_annotations=$(get_field_array_values "${kata_config_file}" "enable_annotations" "${shim}")
				_dbg_kv "existing_annotations" "${existing_annotations}"

				local combined_annotations="${existing_annotations}"
				if [[ -n "${combined_annotations}" ]] && [[ -n "${all_annotations}" ]]; then
					combined_annotations+=",${all_annotations}"
				elif [[ -n "${all_annotations}" ]]; then
					combined_annotations="${all_annotations}"
				fi
				_dbg_kv "combined_annotations" "${combined_annotations}"

				IFS=',' read -a annotations <<< "${combined_annotations}"
				local -A seen_annotations
				local unique_annotations=()

				for annotation in "${annotations[@]}"; do
					annotation=$(echo "${annotation}" | sed 's/^[[:space:]]//;s/[[:space:]]$//')
					if [[ -n "${annotation}" ]] && [[ -z "${seen_annotations[${annotation}]+_}" ]]; then
						seen_annotations["${annotation}"]=1
						unique_annotations+=("${annotation}")
					fi
				done

				_dbg_kv "unique_annotations_count" "${#unique_annotations[@]}"

				if [[ ${#unique_annotations[@]} -gt 0 ]]; then
					local formatted_annotations=()
					for ann in "${unique_annotations[@]}"; do
						formatted_annotations+=("\"${ann}\"")
					done
					local final_annotations
					final_annotations=$(IFS=','; echo "${formatted_annotations[*]}")
					_dbg_kv "final_annotations_toml" "${final_annotations}"
					tomlq -i -t '.hypervisor.'"${hypervisor_name}"'.enable_annotations = ['"${final_annotations}"']' "${kata_config_file}" 2>/dev/null || true
				fi
			fi
		else
			_trace "hypervisor_annotations empty -> skipping"
		fi

		if printf '%s\n' "${experimental_force_guest_pull[@]}" | grep -Fxq "${shim}"; then
			_trace "experimental_force_guest_pull matches ${shim} -> enabling runtime.experimental_force_guest_pull"
			tomlq -i -t '.runtime.experimental_force_guest_pull = true' "${kata_config_file}" 2>/dev/null || true
		fi

		if grep -q "tdx" <<< "$shim"; then
			_trace "shim contains 'tdx' -> checking host distro support"
			VERSION_ID=version_unset
			source /host/etc/os-release || source /host/usr/lib/os-release
			_dbg_kv "ID" "${ID-<unset>}"
			_dbg_kv "VERSION_ID" "${VERSION_ID-<unset>}"
			case ${ID} in
				ubuntu)
					case ${VERSION_ID} in
						24.04|25.04|25.10) tdx_supported ${ID} ${VERSION_ID} ${kata_config_file} ;;
						*) tdx_not_supported ${ID} ${VERSION_ID} ;;
					esac
					;;
				centos)
					case ${VERSION_ID} in
						9) tdx_supported ${ID} ${VERSION_ID} ${kata_config_file} ;;
						*) tdx_not_supported ${ID} ${VERSION_ID} ;;
					esac
					;;
				*) tdx_not_supported ${ID} ${VERSION_ID} ;;
			esac
		fi

		if [ "${dest_dir}" != "${default_dest_dir}" ]; then
			_trace "dest_dir != default_dest_dir -> adjusting paths in config"
			hypervisor="${shim}"
			[[ "${shim}" == "qemu"* ]] && hypervisor="qemu"

			kernel_path=$(tomlq ".hypervisor.${hypervisor}.path" ${kata_config_file} | tr -d \")
			_dbg_kv "kernel_path" "${kernel_path}"

			if echo $kernel_path | grep -q "${dest_dir}"; then
				_trace "kernel_path already contains dest_dir -> break (as in original logic)"
				break
			else
				_trace "sed replace default_dest_dir->dest_dir in ${kata_config_file}"
				sed -i -e "s|${default_dest_dir}|${dest_dir}|g" "${kata_config_file}"

				[[ "${shim}" =~ ^(qemu|qemu-runtime-rs|qemu-snp|qemu-nvidia-gpu|qemu-nvidia-gpu-snp|qemu-nvidia-gpu-tdx|qemu-se|qemu-se-runtime-rs|qemu-coco-dev|qemu-coco-dev-runtime-rs|qemu-cca)$ ]] && \
					adjust_qemu_cmdline "${shim}" "${kata_config_file}"
			fi
		fi
	done

	if [ "${HOST_OS:-}" == "cbl-mariner" ]; then
		_trace "HOST_OS=cbl-mariner -> applying mariner-specific tweaks"
		config_path="${host_install_dir}/share/defaults/kata-containers/configuration-clh.toml"
		clh_path="${dest_dir}/bin/cloud-hypervisor-glibc"
		local mariner_hypervisor_name="clh"

		_dbg_kv "config_path" "${config_path}"
		_dbg_kv "clh_path" "${clh_path}"

		tomlq -i -t '.hypervisor.'"${mariner_hypervisor_name}"'.static_sandbox_resource_mgmt = true' "${config_path}" 2>/dev/null || true

		local existing_paths
		existing_paths=$(tomlq -r '.hypervisor.'"${mariner_hypervisor_name}"'.valid_hypervisor_paths // [] | .[]' "${config_path}" 2>/dev/null || echo "")
		_dbg_kv "existing_paths_raw" "${existing_paths}"

		local path_exists=false
		if [[ -n "${existing_paths}" ]]; then
			while IFS= read -r path; do
				path=$(echo "${path}" | sed 's/^[[:space:]]*//;s/[[:space:]]*$//')
				if [[ "${path}" == "${clh_path}" ]]; then
					path_exists=true
					break
				fi
			done <<< "${existing_paths}"
		fi
		_dbg_kv "path_exists" "${path_exists}"

		if [[ "${path_exists}" == "false" ]]; then
			local formatted_paths=()
			if [[ -n "${existing_paths}" ]]; then
				while IFS= read -r path; do
					path=$(echo "${path}" | sed 's/^[[:space:]]*//;s/[[:space:]]*$//')
					formatted_paths+=("\"${path}\"")
				done <<< "${existing_paths}"
			fi
			formatted_paths+=("\"${clh_path}\"")
			local final_paths
			final_paths=$(IFS=','; echo "${formatted_paths[*]}")
			_dbg_kv "final_paths_toml" "${final_paths}"
			tomlq -i -t '.hypervisor.'"${mariner_hypervisor_name}"'.valid_hypervisor_paths = ['"${final_paths}"']' "${config_path}" 2>/dev/null || true
		fi

		tomlq -i -t '.hypervisor.'"${mariner_hypervisor_name}"'.path = "'"${clh_path}"'"' "${config_path}" 2>/dev/null || true
	fi

	if kubectl get crds nodefeaturerules.nfd.k8s-sigs.io &>/dev/null; then
		_trace "NFD CRD detected"
		arch="$(uname -m)"
		if [[ ${arch} == "x86_64" ]]; then
			node_feature_rule_file="/opt/kata-artifacts/node-feature-rules/${arch}-tee-keys.yaml"
			_dbg_kv "node_feature_rule_file" "${node_feature_rule_file}"

			kubectl apply -f "${node_feature_rule_file}"
			info "As NFD is deployed on the node, rules for ${arch} TEEs have been created"
			patch_runtimeclasses_for_nfd
		else
			_trace "arch=${arch} not x86_64 -> skipping NFD rule apply"
		fi
	else
		_trace "NFD CRD not detected -> skipping"
	fi
	_leave
}

function wait_till_node_is_ready() {
	_enter
	local ready="False"
	_dbg_kv "initial_ready" "${ready}"

	while ! [[ "${ready}" == "True" ]]; do
		_trace "node not ready yet (ready=${ready}) -> sleeping 2s"
		sleep 2s
		ready=$(kubectl get node $NODE_NAME -o jsonpath='{.status.conditions[?(@.type=="Ready")].status}')
		_dbg_kv "ready" "${ready}"
	done

	_trace "node is Ready=True"
	_leave
}

function restart_runtime() {
	_enter "$@"
	local runtime="${1}"
	_dbg_kv "runtime" "${runtime}"

	if [ "${runtime}" == "k0s-worker" ] || [ "${runtime}" == "k0s-controller" ]; then
		_trace "k0s -> no restart"
		:
	elif [ "${runtime}" == "microk8s" ]; then
		_trace "microk8s -> restarting snap.microk8s.daemon-containerd.service"
		host_systemctl restart snap.microk8s.daemon-containerd.service
	else
		_trace "standard -> daemon-reload + restart ${runtime}"
		host_systemctl daemon-reload
		host_systemctl restart "${runtime}"
	fi

	wait_till_node_is_ready
	_leave
}

function configure_cri_runtime() {
	_enter "$@"
	local runtime="${1}"
	_dbg_kv "runtime" "${runtime}"

	case "${runtime}" in
	crio)
		_trace "dispatch -> configure_crio"
		configure_crio
		;;
	containerd | k3s | k3s-agent | rke2-agent | rke2-server | k0s-controller | k0s-worker | microk8s)
		_trace "dispatch -> configure_containerd(${runtime})"
		configure_containerd "${runtime}"
		;;
	esac
	_leave
}

function configure_crio_runtime() {
	_enter "$@"
	local shim="${1}"
	local adjusted_shim_to_multi_install="${shim}"
	if [ -n "${MULTI_INSTALL_SUFFIX}" ]; then
		adjusted_shim_to_multi_install="${shim}-${MULTI_INSTALL_SUFFIX}"
	fi
	local runtime="kata-${adjusted_shim_to_multi_install}"
	local configuration="configuration-${shim}"

	local config_path
	config_path=$(get_kata_containers_config_path "${shim}")

	local kata_path
	kata_path=$(get_kata_containers_runtime_path "${shim}")
	local kata_conf="crio.runtime.runtimes.${runtime}"
	local kata_config_path="${config_path}/${configuration}.toml"

	_dbg_kv "shim" "${shim}"
	_dbg_kv "runtime" "${runtime}"
	_dbg_kv "kata_conf" "${kata_conf}"
	_dbg_kv "kata_path" "${kata_path}"
	_dbg_kv "kata_config_path" "${kata_config_path}"
	_dbg_kv "crio_drop_in_conf_file" "${crio_drop_in_conf_file}"

	cat <<EOF | tee -a "$crio_drop_in_conf_file"

[$kata_conf]
	runtime_path = "${kata_path}"
	runtime_type = "vm"
	runtime_root = "/run/vc"
	runtime_config_path = "${kata_config_path}"
	privileged_without_host_devices = true
EOF

	local key
	local value
	if [[ -n "${PULL_TYPE_MAPPING_FOR_ARCH}" ]]; then
		_trace "PULL_TYPE_MAPPING_FOR_ARCH set -> searching mapping for shim ${shim}"
		for m in "${pull_types[@]}"; do
			key="${m%"$snapshotters_delimiter"*}"
			value="${m#*"$snapshotters_delimiter"}"
			_trace "pull mapping entry: key=${key} value=${value}"

			if [[ "${value}" = "default" || "${key}" != "${shim}" ]]; then
				continue
			fi

			if [ "${value}" == "guest-pull" ]; then
				_trace "guest-pull -> setting runtime_pull_image=true"
				echo -e "\truntime_pull_image = true" | tee -a "${crio_drop_in_conf_file}"
			else
				die "Unsupported pull type '${value}' for ${shim}"
			fi
			break
		done
	else
		_trace "PULL_TYPE_MAPPING_FOR_ARCH empty -> skipping"
	fi
	_leave
}

function configure_crio() {
	_enter
	echo "Add Kata Containers as a supported runtime for CRIO:"
	_dbg_kv "crio_drop_in_conf_dir" "${crio_drop_in_conf_dir}"
	_dbg_kv "crio_drop_in_conf_file" "${crio_drop_in_conf_file}"
	_dbg_kv "crio_drop_in_conf_file_debug" "${crio_drop_in_conf_file_debug}"

	mkdir -p "$crio_drop_in_conf_dir"
	rm -f "$crio_drop_in_conf_file"
	touch "$crio_drop_in_conf_file"
	rm -f "$crio_drop_in_conf_file_debug"
	touch "$crio_drop_in_conf_file_debug"

	cat <<EOF | tee -a "$crio_drop_in_conf_file"
[crio]
  storage_option = [
	"overlay.skip_mount_home=true",
  ]
EOF

	for shim in "${shims[@]}"; do
		_trace "configure_crio -> configure_crio_runtime ${shim}"
		configure_crio_runtime $shim
	done

	if [ "${DEBUG}" == "true" ]; then
		_trace "DEBUG=true -> writing CRIO debug config"
		cat <<EOF | tee $crio_drop_in_conf_file_debug
[crio.runtime]
log_level = "debug"
EOF
	else
		_trace "DEBUG!=true -> skipping CRIO debug config"
	fi
	_leave
}

function configure_containerd_runtime() {
	_enter "$@"
	local shim="$2"
	local adjusted_shim_to_multi_install="${shim}"
	if [ -n "${MULTI_INSTALL_SUFFIX}" ]; then
		adjusted_shim_to_multi_install="${shim}-${MULTI_INSTALL_SUFFIX}"
	fi
	local runtime="kata-${adjusted_shim_to_multi_install}"
	local configuration="configuration-${shim}"
	local pluginid=cri
	local configuration_file="${containerd_conf_file}"

	_dbg_kv "runtime_arg1" "$1"
	_dbg_kv "shim" "${shim}"
	_dbg_kv "runtime_name" "${runtime}"
	_dbg_kv "containerd_conf_file" "${containerd_conf_file}"
	_dbg_kv "use_containerd_drop_in_conf_file" "${use_containerd_drop_in_conf_file}"
	_dbg_kv "containerd_drop_in_conf_file" "${containerd_drop_in_conf_file}"

	if [ $use_containerd_drop_in_conf_file = "true" ]; then
		configuration_file="/host${containerd_drop_in_conf_file}"
		_trace "using drop-in configuration file: ${configuration_file}"
	else
		_trace "using root configuration file: ${configuration_file}"
	fi

	local containerd_root_conf_file="$containerd_conf_file"
	if [[ "$1" =~ ^(k0s-worker|k0s-controller)$ ]]; then
		containerd_root_conf_file="/etc/containerd/containerd.toml"
		_trace "k0s -> containerd_root_conf_file=${containerd_root_conf_file}"
	fi

	if grep -q "version = 2\>" $containerd_root_conf_file; then
		pluginid=\"io.containerd.grpc.v1.cri\"
		_trace "detected containerd config version=2 -> pluginid=${pluginid}"
	fi

	if grep -q "version = 3\>" $containerd_root_conf_file; then
		pluginid=\"io.containerd.cri.v1.runtime\"
		_trace "detected containerd config version=3 -> pluginid=${pluginid}"
	fi

	local runtime_table=".plugins.${pluginid}.containerd.runtimes.\"${runtime}\""
	local runtime_options_table="${runtime_table}.options"
	local runtime_type=\"io.containerd."${runtime}".v2\"
	local runtime_config_path=\"$(get_kata_containers_config_path "${shim}")/${configuration}.toml\"
	local runtime_path=\"$(get_kata_containers_runtime_path "${shim}")\"

	_dbg_kv "runtime_table" "${runtime_table}"
	_dbg_kv "runtime_options_table" "${runtime_options_table}"
	_dbg_kv "runtime_type" "${runtime_type}"
	_dbg_kv "runtime_config_path" "${runtime_config_path}"
	_dbg_kv "runtime_path" "${runtime_path}"
	_dbg_kv "configuration_file" "${configuration_file}"

	tomlq -i -t $(printf '%s.runtime_type=%s' ${runtime_table} ${runtime_type}) ${configuration_file}
	tomlq -i -t $(printf '%s.runtime_path=%s' ${runtime_table} ${runtime_path}) ${configuration_file}
	tomlq -i -t $(printf '%s.privileged_without_host_devices=true' ${runtime_table}) ${configuration_file}

	if [[ "${shim}" == *"nvidia-gpu-"* ]]; then
		_trace "nvidia-gpu shim -> adding extra pod_annotations"
		tomlq -i -t $(printf '%s.pod_annotations=["io.katacontainers.*","cdi.k8s.io/*"]' ${runtime_table}) ${configuration_file}
	else
		tomlq -i -t $(printf '%s.pod_annotations=["io.katacontainers.*"]' ${runtime_table}) ${configuration_file}
	fi

	tomlq -i -t $(printf '%s.ConfigPath=%s' ${runtime_options_table} ${runtime_config_path}) ${configuration_file}

	if [ "${DEBUG}" == "true" ]; then
		_trace "DEBUG=true -> setting .debug.level=debug"
		tomlq -i -t '.debug.level = "debug"' ${configuration_file}
	fi

	if [[ -n "${SNAPSHOTTER_HANDLER_MAPPING_FOR_ARCH}" ]]; then
		_trace "SNAPSHOTTER_HANDLER_MAPPING_FOR_ARCH set -> applying per-shim snapshotter"
		for m in "${snapshotters[@]}"; do
			key="${m%$snapshotters_delimiter*}"
			if [ "${key}" != "${shim}" ]; then
				continue
			fi

			value="${m#*$snapshotters_delimiter}"
			_trace "snapshotter mapping for ${shim}: ${value}"
			if [[ "${value}" == "nydus" ]] && [[ -n "${MULTI_INSTALL_SUFFIX}" ]]; then
				value="${value}-${MULTI_INSTALL_SUFFIX}"
				_trace "multi-install -> snapshotter renamed to ${value}"
			fi

			tomlq -i -t $(printf '%s.snapshotter="%s"' ${runtime_table} ${value}) ${configuration_file}
			break
		done
	else
		_trace "SNAPSHOTTER_HANDLER_MAPPING_FOR_ARCH empty -> not setting snapshotter"
	fi
	_leave
}

function configure_containerd() {
	_enter "$@"
	echo "Add Kata Containers as a supported runtime for containerd"
	_dbg_kv "runtime" "$1"
	_dbg_kv "containerd_conf_file" "${containerd_conf_file}"
	_dbg_kv "use_containerd_drop_in_conf_file" "${use_containerd_drop_in_conf_file}"
	_dbg_kv "containerd_drop_in_conf_file" "${containerd_drop_in_conf_file}"
	_dbg_kv "create_containerd_conf_backup" "${create_containerd_conf_backup}"

	mkdir -p /etc/containerd/

	if [ $use_containerd_drop_in_conf_file = "false" ] && [ -f "$containerd_conf_file" ]; then
		_trace "drop-ins unsupported -> backups disabled by design, skipping backup creation"
		:
	fi

	if [ $use_containerd_drop_in_conf_file = "true" ]; then
		_trace "drop-ins supported -> writing kata.toml.tmpl + ensuring imports"
		write_containerd_kata_template "${containerd_drop_in_conf_file}"

		local kata_containerd_prefix="${dest_dir}/containerd/"
		_dbg_kv "kata_containerd_prefix" "${kata_containerd_prefix}"

		ensure_containerd_imports "/etc/containerd/config.toml" "${kata_containerd_prefix}" "${containerd_drop_in_conf_file}"
		ensure_containerd_imports "${containerd_conf_file}" "${kata_containerd_prefix}" "${containerd_drop_in_conf_file}"
	else
		_trace "drop-ins not supported -> skipping kata.toml.tmpl and imports edits"
	fi

	for shim in "${shims[@]}"; do
		_trace "configure_containerd -> configure_containerd_runtime $1 ${shim}"
		configure_containerd_runtime "$1" $shim
	done
	_leave
}

function remove_artifacts() {
	_enter
	echo "deleting kata artifacts"
	_dbg_kv "host_install_dir" "${host_install_dir}"

	rm -rf ${host_install_dir}

	if kubectl get crds nodefeaturerules.nfd.k8s-sigs.io &>/dev/null; then
		_trace "NFD CRD detected -> deleting node-feature rules"
		arch="$(uname -m)"
		if [[ ${arch} == "x86_64" ]]; then
			node_feature_rule_file="/opt/kata-artifacts/node-feature-rules/${arch}-tee-keys.yaml"
			_dbg_kv "node_feature_rule_file" "${node_feature_rule_file}"
			kubectl delete --ignore-not-found -f "${node_feature_rule_file}"
			info "As NFD is deployed on the node, rules for ${arch} TEEs have been deleted"
		fi
	fi
	_leave
}

function restart_cri_runtime() {
	_enter "$@"
	local runtime="${1}"
	_dbg_kv "runtime" "${runtime}"

	if [ "${runtime}" == "k0s-worker" ] || [ "${runtime}" == "k0s-controller" ]; then
		_trace "k0s -> no restart"
		:
	elif [ "$1" == "microk8s" ]; then
		_trace "microk8s -> restart snap.microk8s.daemon-containerd.service"
		host_systemctl restart snap.microk8s.daemon-containerd.service
	else
		_trace "standard -> daemon-reload + restart ${runtime}"
		host_systemctl daemon-reload
		host_systemctl restart "${runtime}"
	fi
	_leave
}

function cleanup_cri_runtime() {
	_enter "$@"
	case $1 in
	crio) _trace "cleanup dispatch -> cleanup_crio"; cleanup_crio ;;
	containerd | k3s | k3s-agent | rke2-agent | rke2-server | k0s-controller | k0s-worker | microk8s)
		_trace "cleanup dispatch -> cleanup_containerd"
		cleanup_containerd
		;;
	esac

	[ "${HELM_POST_DELETE_HOOK}" == "false" ] && { _trace "HELM_POST_DELETE_HOOK=false -> return"; _leave; return; }

	_trace "HELM_POST_DELETE_HOOK=true -> restart_cri_runtime"
	restart_cri_runtime "$1"
	_leave
}

function cleanup_crio() {
	_enter
	_dbg_kv "crio_drop_in_conf_file" "${crio_drop_in_conf_file}"
	rm -f $crio_drop_in_conf_file
	if [[ "${DEBUG}" == "true" ]]; then
		_dbg_kv "crio_drop_in_conf_file_debug" "${crio_drop_in_conf_file_debug}"
		rm -f $crio_drop_in_conf_file_debug
	fi
	_leave
}

function cleanup_containerd() {
	_enter
	_dbg_kv "use_containerd_drop_in_conf_file" "${use_containerd_drop_in_conf_file}"
	_dbg_kv "containerd_conf_file" "${containerd_conf_file}"
	_dbg_kv "containerd_drop_in_conf_file" "${containerd_drop_in_conf_file}"

	if [ $use_containerd_drop_in_conf_file = "true" ]; then
		_trace "drop-ins supported -> removing imports (safe) + removing kata.toml.tmpl"
		remove_containerd_import "/etc/containerd/config.toml" "${containerd_drop_in_conf_file}"
		remove_containerd_import "${containerd_conf_file}" "${containerd_drop_in_conf_file}"
		rm -f "/etc/containerd/kata.toml.tmpl"
		_leave
		return
	fi

	if [ -f "$containerd_conf_file_backup" ]; then
		_trace "backup exists -> revert config"
		rm -f $containerd_conf_file
		mv "$containerd_conf_file_backup" "$containerd_conf_file"
	else
		warn "No backup found (${containerd_conf_file_backup}); leaving ${containerd_conf_file} as-is"
	fi
	_leave
}

function reset_runtime() {
	_enter "$@"
	kubectl label node "$NODE_NAME" katacontainers.io/kata-runtime-
	restart_cri_runtime "$1"

	if [ "$1" == "crio" ] || [ "$1" == "containerd" ]; then
		_trace "runtime is crio/containerd -> restarting kubelet"
		host_systemctl restart kubelet
	fi

	wait_till_node_is_ready
	_leave
}

function containerd_snapshotter_version_check() {
	_enter
	local container_runtime_version
	container_runtime_version=$(kubectl get node $NODE_NAME -o jsonpath='{.status.nodeInfo.containerRuntimeVersion}')
	local containerd_prefix="containerd://"
	local containerd_version_to_avoid="1.6"
	local containerd_version=${container_runtime_version#$containerd_prefix}

	_dbg_kv "container_runtime_version" "${container_runtime_version}"
	_dbg_kv "containerd_version" "${containerd_version}"

	if grep -q ^${containerd_version_to_avoid} <<< ${containerd_version}; then
		_trace "containerd version starts with ${containerd_version_to_avoid}"
		if [[ -n "${SNAPSHOTTER_HANDLER_MAPPING_FOR_ARCH}" ]]; then
			die "kata-deploy only supports snapshotter configuration with containerd 1.7 or newer"
		fi
	fi
	_leave
}

function containerd_erofs_snapshotter_version_check() {
	_enter
	local container_runtime_version
	container_runtime_version=$(kubectl get node $NODE_NAME -o jsonpath='{.status.nodeInfo.containerRuntimeVersion}')
	local containerd_prefix="containerd://"
	local containerd_version=${container_runtime_version#$containerd_prefix}
	local min_version_major="2"
	local min_version_minor="2"

	_dbg_kv "container_runtime_version" "${container_runtime_version}"
	_dbg_kv "containerd_version" "${containerd_version}"

	local major=${containerd_version%%.*}
	local rest=${containerd_version#*.}
	local minor=${rest%%[^0-9]*}

	_dbg_kv "major" "${major}"
	_dbg_kv "minor" "${minor}"

	if [ "${min_version_major}" -gt "${major}" ] || { [ "${min_version_major}" -eq "${major}" ] && [ "${min_version_minor}" -gt "${minor}" ]; }; then
		die "In order to use erofs-snapshotter containerd must be 2.2.0 or newer"
	fi
	_leave
}

function snapshotter_handler_mapping_validation_check() {
	_enter
	echo "Validating the snapshotter-handler mapping: \"${SNAPSHOTTER_HANDLER_MAPPING_FOR_ARCH}\""
	if [[ -z "${SNAPSHOTTER_HANDLER_MAPPING_FOR_ARCH}" ]]; then
		echo "No snapshotter has been requested, using the default value from containerd"
		_leave
		return
	fi

	for m in "${snapshotters[@]}"; do
		shim="${m%$snapshotters_delimiter*}"
		snapshotter="${m#*$snapshotters_delimiter}"
		_trace "mapping entry: shim=${shim} snapshotter=${snapshotter}"

		if [ -z "${shim}" ]; then
			die "The snapshotter must follow the \"shim:snapshotter,shim:snapshotter,...\" format, but at least one shim is empty"
		fi

		if [ -z "${snapshotter}" ]; then
			die "The snapshotter must follow the \"shim:snapshotter,shim:snapshotter,...\" format, but at least one snapshotter is empty"
		fi

		if ! grep -q " ${shim} " <<< " ${SHIMS_FOR_ARCH} "; then
			die "\"${shim}\" is not part of \"${SHIMS_FOR_ARCH}\""
		fi

		matches=$(grep -o "${shim}${snapshotters_delimiter}" <<< "${SNAPSHOTTER_HANDLER_MAPPING_FOR_ARCH}" | wc -l)
		_dbg_kv "matches_for_${shim}" "${matches}"
		if [[ ${matches} -ne 1 ]]; then
			die "One, and only one, entry per shim is required"
		fi
	done
	_leave
}

function configure_erofs_snapshotter() {
	_enter "$@"
	info "Configuring erofs-snapshotter"
	configuration_file="${1}"
	_dbg_kv "configuration_file" "${configuration_file}"

	tomlq -i -t $(printf '.plugins."io.containerd.cri.v1.images".discard_unpacked_layers=false') ${configuration_file}
	tomlq -i -t $(printf '.plugins."io.containerd.service.v1.diff-service".default=["erofs","walking"]') ${configuration_file}
	tomlq -i -t $(printf '.plugins."io.containerd.snapshotter.v1.erofs".enable_fsverity=true') ${configuration_file}
	tomlq -i -t $(printf '.plugins."io.containerd.snapshotter.v1.erofs".set_immutable=true') ${configuration_file}
	_leave
}

function configure_nydus_snapshotter() {
	_enter "$@"
	info "Configuring nydus-snapshotter"

	local nydus="nydus"
	local containerd_nydus="nydus-snapshotter"
	if [[ -n "${MULTI_INSTALL_SUFFIX}" ]]; then
		nydus="${nydus}-${MULTI_INSTALL_SUFFIX}"
		containerd_nydus="${containerd_nydus}-${MULTI_INSTALL_SUFFIX}"
	fi

	configuration_file="${1}"
	pluginid="${2}"

	_dbg_kv "configuration_file" "${configuration_file}"
	_dbg_kv "pluginid" "${pluginid}"
	_dbg_kv "nydus" "${nydus}"
	_dbg_kv "containerd_nydus" "${containerd_nydus}"

	tomlq -i -t $(printf '.plugins.%s.disable_snapshot_annotations=false' ${pluginid}) ${configuration_file}
	tomlq -i -t $(printf '.proxy_plugins."%s".type="snapshot"' ${nydus} ) ${configuration_file}
	tomlq -i -t $(printf '.proxy_plugins."%s".address="/run/%s/containerd-nydus-grpc.sock"' ${nydus} ${containerd_nydus}) ${configuration_file}
	_leave
}

function configure_snapshotter() {
	_enter "$@"
	snapshotter="${1}"
	_dbg_kv "snapshotter" "${snapshotter}"

	local runtime
	runtime="$(get_container_runtime)"
	local pluginid="\"io.containerd.grpc.v1.cri\".containerd"
	local configuration_file="${containerd_conf_file}"

	if [[ ${use_containerd_drop_in_conf_file} == "true" ]]; then
		configuration_file="/host${containerd_drop_in_conf_file}"
	fi

	_dbg_kv "runtime" "${runtime}"
	_dbg_kv "pluginid_initial" "${pluginid}"
	_dbg_kv "configuration_file" "${configuration_file}"

	local containerd_root_conf_file="${containerd_conf_file}"
	if [[ "${runtime}" =~ ^(k0s-worker|k0s-controller)$ ]]; then
		containerd_root_conf_file="/etc/containerd/containerd.toml"
	fi
	_dbg_kv "containerd_root_conf_file" "${containerd_root_conf_file}"

	if grep -q "version = 3\>" ${containerd_root_conf_file}; then
		pluginid=\"io.containerd.cri.v1.images\"
		_dbg_kv "pluginid_adjusted" "${pluginid}"
	fi

	case "${snapshotter}" in
		nydus)
			configure_nydus_snapshotter "${configuration_file}" "${pluginid}"

			nydus_snapshotter="nydus-snapshotter"
			if [[ -n "${MULTI_INSTALL_SUFFIX}" ]]; then
				nydus_snapshotter="${nydus_snapshotter}-${MULTI_INSTALL_SUFFIX}"
			fi
			_dbg_kv "nydus_snapshotter_service" "${nydus_snapshotter}"
			host_systemctl restart "${nydus_snapshotter}"
			;;
		erofs)
			configure_erofs_snapshotter "${configuration_file}"
			;;
	esac
	_leave
}

function install_nydus_snapshotter() {
	_enter
	info "Deploying nydus-snapshotter"

	local nydus_snapshotter="nydus-snapshotter"
	if [[ -n "${MULTI_INSTALL_SUFFIX}" ]]; then
		nydus_snapshotter="${nydus_snapshotter}-${MULTI_INSTALL_SUFFIX}"
	fi

	local config_guest_pulling="/opt/kata-artifacts/nydus-snapshotter/config-guest-pulling.toml"
	local nydus_snapshotter_service="/opt/kata-artifacts/nydus-snapshotter/nydus-snapshotter.service"

	_dbg_kv "nydus_snapshotter" "${nydus_snapshotter}"
	_dbg_kv "config_guest_pulling" "${config_guest_pulling}"
	_dbg_kv "nydus_snapshotter_service" "${nydus_snapshotter_service}"

	sed -i -e "s|@SNAPSHOTTER_ROOT_DIR@|/var/lib/${nydus_snapshotter}|g" "${config_guest_pulling}"
	sed -i -e "s|@SNAPSHOTTER_GRPC_SOCKET_ADDRESS@|/run/${nydus_snapshotter}/containerd-nydus-grpc.sock|g" "${config_guest_pulling}"
	sed -i -e "s|@NYDUS_OVERLAYFS_PATH@|${host_install_dir#/host}/nydus-snapshotter/nydus-overlayfs|g" "${config_guest_pulling}"

	sed -i -e "s|@CONTAINERD_NYDUS_GRPC_BINARY@|${host_install_dir#/host}/nydus-snapshotter/containerd-nydus-grpc|g" "${nydus_snapshotter_service}"
	sed -i -e "s|@CONFIG_GUEST_PULLING@|${host_install_dir#/host}/nydus-snapshotter/config-guest-pulling.toml|g" "${nydus_snapshotter_service}"

	mkdir -p "${host_install_dir}/nydus-snapshotter"
	install -D -m 775 /opt/kata-artifacts/nydus-snapshotter/containerd-nydus-grpc "${host_install_dir}/nydus-snapshotter/containerd-nydus-grpc"
	install -D -m 775 /opt/kata-artifacts/nydus-snapshotter/nydus-overlayfs "${host_install_dir}/nydus-snapshotter/nydus-overlayfs"

	install -D -m 644 "${config_guest_pulling}" "${host_install_dir}/nydus-snapshotter/config-guest-pulling.toml"
	install -D -m 644 "${nydus_snapshotter_service}" "/host/etc/systemd/system/${nydus_snapshotter}.service"

	host_systemctl daemon-reload
	host_systemctl enable "${nydus_snapshotter}.service"
	_leave
}

function uninstall_nydus_snapshotter() {
	_enter
	info "Removing deployed nydus-snapshotter"

	local nydus_snapshotter="nydus-snapshotter"
	if [[ -n "${MULTI_INSTALL_SUFFIX}" ]]; then
		nydus_snapshotter="${nydus_snapshotter}-${MULTI_INSTALL_SUFFIX}"
	fi
	_dbg_kv "nydus_snapshotter" "${nydus_snapshotter}"

	host_systemctl disable --now "${nydus_snapshotter}.service"

	rm -f "/host/etc/systemd/system/${nydus_snapshotter}.service"
	rm -rf "${host_install_dir}/nydus-snapshotter"

	host_systemctl daemon-reload
	_leave
}

function install_snapshotter() {
	_enter "$@"
	snapshotter="${1}"
	_dbg_kv "snapshotter" "${snapshotter}"

	case "${snapshotter}" in
		erofs) _trace "erofs is built-in -> no install" ;;
		nydus) install_nydus_snapshotter ;;
	esac
	_leave
}

function uninstall_snapshotter() {
	_enter "$@"
	snapshotter="${1}"
	_dbg_kv "snapshotter" "${snapshotter}"

	case "${snapshotter}" in
		nydus) uninstall_nydus_snapshotter ;;
	esac
	_leave
}

function main() {
	_enter "$@"
	action=${1:-}
	if [ -z "$action" ]; then
		print_usage
		die "invalid arguments"
	fi

	echo "Action:"
	echo "* $action"
	echo ""

	echo "Environment variables passed to this script"
	echo "* NODE_NAME: ${NODE_NAME}"
	echo "* DEBUG: ${DEBUG}"
	echo "* SHIMS_X86_64: ${SHIMS_X86_64}"
	echo "* SHIMS_AARCH64: ${SHIMS_AARCH64}"
	echo "* SHIMS_S390X: ${SHIMS_S390X}"
	echo "* SHIMS_PPC64LE: ${SHIMS_PPC64LE}"
	echo "* DEFAULT_SHIM_X86_64: ${DEFAULT_SHIM_X86_64}"
	echo "* DEFAULT_SHIM_AARCH64: ${DEFAULT_SHIM_AARCH64}"
	echo "* DEFAULT_SHIM_S390X: ${DEFAULT_SHIM_S390X}"
	echo "* DEFAULT_SHIM_PPC64LE: ${DEFAULT_SHIM_PPC64LE}"
	echo "* ALLOWED_HYPERVISOR_ANNOTATIONS_X86_64: ${ALLOWED_HYPERVISOR_ANNOTATIONS_X86_64}"
	echo "* ALLOWED_HYPERVISOR_ANNOTATIONS_AARCH64: ${ALLOWED_HYPERVISOR_ANNOTATIONS_AARCH64}"
	echo "* ALLOWED_HYPERVISOR_ANNOTATIONS_S390X: ${ALLOWED_HYPERVISOR_ANNOTATIONS_S390X}"
	echo "* ALLOWED_HYPERVISOR_ANNOTATIONS_PPC64LE: ${ALLOWED_HYPERVISOR_ANNOTATIONS_PPC64LE}"
	echo "* SNAPSHOTTER_HANDLER_MAPPING_X86_64: ${SNAPSHOTTER_HANDLER_MAPPING_X86_64}"
	echo "* SNAPSHOTTER_HANDLER_MAPPING_AARCH64: ${SNAPSHOTTER_HANDLER_MAPPING_AARCH64}"
	echo "* SNAPSHOTTER_HANDLER_MAPPING_S390X: ${SNAPSHOTTER_HANDLER_MAPPING_S390X}"
	echo "* SNAPSHOTTER_HANDLER_MAPPING_PPC64LE: ${SNAPSHOTTER_HANDLER_MAPPING_PPC64LE}"
	echo "* AGENT_HTTPS_PROXY: ${AGENT_HTTPS_PROXY}"
	echo "* AGENT_NO_PROXY: ${AGENT_NO_PROXY}"
	echo "* PULL_TYPE_MAPPING_X86_64: ${PULL_TYPE_MAPPING_X86_64}"
	echo "* PULL_TYPE_MAPPING_AARCH64: ${PULL_TYPE_MAPPING_AARCH64}"
	echo "* PULL_TYPE_MAPPING_S390X: ${PULL_TYPE_MAPPING_S390X}"
	echo "* PULL_TYPE_MAPPING_PPC64LE: ${PULL_TYPE_MAPPING_PPC64LE}"
	echo "* INSTALLATION_PREFIX: ${INSTALLATION_PREFIX}"
	echo "* MULTI_INSTALL_SUFFIX: ${MULTI_INSTALL_SUFFIX}"
	echo "* HELM_POST_DELETE_HOOK: ${HELM_POST_DELETE_HOOK}"
	echo "* EXPERIMENTAL_SETUP_SNAPSHOTTER: ${EXPERIMENTAL_SETUP_SNAPSHOTTER}"
	echo "* EXPERIMENTAL_FORCE_GUEST_PULL_X86_64: ${EXPERIMENTAL_FORCE_GUEST_PULL_X86_64}"
	echo "* EXPERIMENTAL_FORCE_GUEST_PULL_AARCH64: ${EXPERIMENTAL_FORCE_GUEST_PULL_AARCH64}"
	echo "* EXPERIMENTAL_FORCE_GUEST_PULL_S390X: ${EXPERIMENTAL_FORCE_GUEST_PULL_S390X}"
	echo "* EXPERIMENTAL_FORCE_GUEST_PULL_PPC64LE: ${EXPERIMENTAL_FORCE_GUEST_PULL_PPC64LE}"

	if [[ "${TRACE_DUMP_ENV}" == "true" ]]; then
		echo "" >&2
		echo "TRACE: $(_now_ts) Derived/important variables (post-init):" >&2
		_dbg_kv "ARCH" "${ARCH}"
		_dbg_kv "SHIMS_FOR_ARCH" "${SHIMS_FOR_ARCH}"
		_dbg_kv "DEFAULT_SHIM_FOR_ARCH" "${DEFAULT_SHIM_FOR_ARCH}"
		_dbg_kv "SNAPSHOTTER_HANDLER_MAPPING_FOR_ARCH" "${SNAPSHOTTER_HANDLER_MAPPING_FOR_ARCH}"
		_dbg_kv "ALLOWED_HYPERVISOR_ANNOTATIONS_FOR_ARCH" "${ALLOWED_HYPERVISOR_ANNOTATIONS_FOR_ARCH}"
		_dbg_kv "PULL_TYPE_MAPPING_FOR_ARCH" "${PULL_TYPE_MAPPING_FOR_ARCH}"
		_dbg_kv "EXPERIMENTAL_FORCE_GUEST_PULL_FOR_ARCH" "${EXPERIMENTAL_FORCE_GUEST_PULL_FOR_ARCH}"
		_dbg_kv "dest_dir" "${dest_dir}"
		_dbg_kv "host_install_dir" "${host_install_dir}"
		_dbg_kv "containerd_drop_in_conf_file" "${containerd_drop_in_conf_file}"
		_dbg_kv "containerd_conf_file" "${containerd_conf_file}"
		_dbg_kv "containerd_conf_tmpl_file" "${containerd_conf_tmpl_file}"
		_dbg_kv "containerd_conf_file_backup" "${containerd_conf_file_backup}"
	fi

	euid=$(id -u)
	_dbg_kv "EUID" "${euid}"
	if [[ $euid -ne 0 ]]; then
		die "This script must be run as root"
	fi

	_trace "calling get_container_runtime"
	runtime=$(get_container_runtime)
	_dbg_kv "detected_runtime" "${runtime}"

	if [ "$runtime" == "cri-o" ]; then
		_trace "normalizing cri-o -> crio"
		runtime="crio"
	elif [ "$runtime" == "microk8s" ]; then
		_trace "microk8s -> containerd_conf_file containerd-template.toml"
		containerd_conf_file="/etc/containerd/containerd-template.toml"
		containerd_conf_file_backup="${containerd_conf_file}.bak"
	elif [[ "$runtime" =~ ^(k3s|k3s-agent|rke2-agent|rke2-server)$ ]]; then
		_trace "k3s/rke2 -> containerd_conf_tmpl_file=${containerd_conf_file}.tmpl"
		containerd_conf_tmpl_file="${containerd_conf_file}.tmpl"
		containerd_conf_file_backup="${containerd_conf_tmpl_file}.bak"
	elif [[ "$runtime" =~ ^(k0s-worker|k0s-controller)$ ]]; then
		_trace "k0s -> using /etc/containerd/containerd.d/kata-containers*.toml"
		containerd_conf_file="/etc/containerd/containerd.d/kata-containers.toml"
		if [ -n "$MULTI_INSTALL_SUFFIX" ]; then
			containerd_conf_file="/etc/containerd/containerd.d/kata-containers-$MULTI_INSTALL_SUFFIX.toml"
		fi
		containerd_conf_file_backup="${containerd_conf_tmpl_file}.bak"
	fi

	_dbg_kv "runtime_normalized" "${runtime}"
	_dbg_kv "containerd_conf_file" "${containerd_conf_file}"
	_dbg_kv "containerd_conf_tmpl_file" "${containerd_conf_tmpl_file}"
	_dbg_kv "containerd_conf_file_backup" "${containerd_conf_file_backup}"

	if [[ "$runtime" =~ ^(crio|containerd|k3s|k3s-agent|rke2-agent|rke2-server|k0s-worker|k0s-controller|microk8s)$ ]]; then
		_trace "runtime supported for install/cleanup/reset path"

		if [ "$runtime" != "crio" ]; then
			containerd_snapshotter_version_check
			snapshotter_handler_mapping_validation_check

			use_containerd_drop_in_conf_file=$(is_containerd_capable_of_using_drop_in_files "$runtime")
			echo "Using containerd drop-in files: $use_containerd_drop_in_conf_file"

			if [[ ! "$runtime" =~ ^(k0s-worker|k0s-controller)$ ]]; then
				if [ -n "$MULTI_INSTALL_SUFFIX" ] && [ $use_containerd_drop_in_conf_file = "false" ]; then
					die "Multi installation can only be done if $runtime supports drop-in configuration files"
				fi
			fi
		fi

		case "$action" in
		install)
			_trace "action=install"
			if [[ -n "${EXPERIMENTAL_SETUP_SNAPSHOTTER}" ]]; then
				_trace "EXPERIMENTAL_SETUP_SNAPSHOTTER set -> validating"
				if [[ "${runtime}" == "cri-o" ]]; then
					warn "EXPERIMENTAL_SETUP_SNAPSHOTTER is being ignored!"
					warn "Snapshotter is a containerd specific option."
				else
					for snapshotter in "${experimental_setup_snapshotter[@]}"; do
						_trace "experimental snapshotter: ${snapshotter}"
						case "${snapshotter}" in
							erofs) containerd_erofs_snapshotter_version_check ;;
							nydus) ;;
							*) die "${EXPERIMENTAL_SETUP_SNAPSHOTTER} is not a supported snapshotter by kata-deploy" ;;
						esac
					done
				fi
			fi

			if [[ "$runtime" =~ ^(k3s|k3s-agent|rke2-agent|rke2-server)$ ]]; then
				_trace "runtime is k3s/rke2 -> ensure template file exists"
				if [ ! -f "$containerd_conf_tmpl_file" ] && [ -f "$containerd_conf_file" ]; then
					_trace "copy ${containerd_conf_file} -> ${containerd_conf_tmpl_file}"
					cp "$containerd_conf_file" "$containerd_conf_tmpl_file"
				fi
				containerd_conf_file="${containerd_conf_tmpl_file}"
				containerd_conf_file_backup="${containerd_conf_tmpl_file}.bak"
			elif [[ "$runtime" =~ ^(k0s-worker|k0s-controller)$ ]]; then
				_trace "k0s -> touch ${containerd_conf_file}"
				mkdir -p "$(dirname "$containerd_conf_file")"
				touch "$containerd_conf_file"
			elif [[ "$runtime" == "containerd" ]]; then
				_trace "raw containerd -> generate config default if missing"
				if [ ! -f "$containerd_conf_file" ] && [ -d "$(dirname "$containerd_conf_file")" ]; then
					host_exec containerd config default > "$containerd_conf_file"
				fi
			fi

			if [ $use_containerd_drop_in_conf_file = "true" ]; then
				_trace "drop-ins enabled -> ensure /host drop-in exists: ${containerd_drop_in_conf_file}"
				mkdir -p "$(dirname "/host$containerd_drop_in_conf_file")"
				touch "/host$containerd_drop_in_conf_file"
			fi

			install_artifacts
			configure_cri_runtime "$runtime"

			for snapshotter in "${experimental_setup_snapshotter[@]}"; do
				install_snapshotter "${snapshotter}"
				configure_snapshotter "${snapshotter}"
			done

			restart_runtime "${runtime}"
			kubectl label node "$NODE_NAME" --overwrite katacontainers.io/kata-runtime=true
			;;
		cleanup)
			_trace "action=cleanup"
			if [[ "$runtime" =~ ^(k3s|k3s-agent|rke2-agent|rke2-server)$ ]]; then
				containerd_conf_file_backup="${containerd_conf_tmpl_file}.bak"
				containerd_conf_file="${containerd_conf_tmpl_file}"
			fi

			local kata_deploy_installations
			kata_deploy_installations=$(kubectl -n kube-system get ds | grep kata-deploy | wc -l)
			_dbg_kv "kata_deploy_installations" "${kata_deploy_installations}"

			if [ "${HELM_POST_DELETE_HOOK}" == "true" ]; then
				_trace "HELM_POST_DELETE_HOOK=true"
				if [ $kata_deploy_installations -eq 0 ]; then
					kubectl label node "$NODE_NAME" katacontainers.io/kata-runtime-
				fi
			fi

			for snapshotter in "${experimental_setup_snapshotter[@]}"; do
				_trace "uninstall_snapshotter called with EXPERIMENTAL_SETUP_SNAPSHOTTER=${EXPERIMENTAL_SETUP_SNAPSHOTTER}"
				uninstall_snapshotter "${EXPERIMENTAL_SETUP_SNAPSHOTTER}"
			done

			cleanup_cri_runtime "$runtime"

			if [ "${HELM_POST_DELETE_HOOK}" == "false" ]; then
				_trace "HELM_POST_DELETE_HOOK=false"
				if [ $kata_deploy_installations -eq 0 ]; then
					kubectl label node "$NODE_NAME" --overwrite katacontainers.io/kata-runtime=cleanup
				fi
			fi

			remove_artifacts

			if [ "${HELM_POST_DELETE_HOOK}" == "true" ]; then
				exit 0
			fi
			;;
		reset)
			_trace "action=reset"
			reset_runtime $runtime
			;;
		*)
			print_usage
			die "invalid arguments"
			;;
		esac
	else
		_trace "runtime not supported by kata-deploy script flow -> no-op"
	fi

	# It is assumed this script will be called as a daemonset. As a result, do
	# not return, otherwise the daemon will restart and rexecute the script
	_trace "sleeping infinity (daemonset behavior)"
	sleep infinity
}

main "$@"
