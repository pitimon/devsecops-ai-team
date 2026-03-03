#!/usr/bin/env bash
set -euo pipefail

# DevSecOps AI Team -- DAG Pipeline Engine
# Parses YAML pipeline definitions, performs topological sort, executes nodes
#
# Usage:
#   pipeline-engine.sh validate <pipeline.yml>
#   pipeline-engine.sh run <pipeline.yml> [--target T] [--output-dir D]
#   pipeline-engine.sh to-json <pipeline.yml>
#   pipeline-engine.sh list
#   pipeline-engine.sh status [--run-id ID]
#   pipeline-engine.sh rerun <pipeline.yml> --node NAME

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
PIPELINES_DIR="$SCRIPT_DIR/pipelines"
OUTPUT_DIR="${OUTPUT_DIR:-$REPO_ROOT/output}"
STATE_FILE="$OUTPUT_DIR/pipeline-state.json"
SCAN_TARGET="${SCAN_TARGET:-.}"
VALID_NODE_TYPES="scanner normalizer dedup deduplicator formatter compliance enricher gate storage"

# ---- Helpers: YAML parsing ------------------------------------------------

# Convert YAML pipeline to JSON using python3
yaml_to_json() {
  local yaml_file="$1"
  python3 -c "
import yaml, json, sys
try:
    data = yaml.safe_load(open('$yaml_file'))
    json.dump(data, sys.stdout)
except Exception as e:
    print(f'ERROR: {e}', file=sys.stderr)
    sys.exit(1)
"
}

# Extract pipeline name from YAML
pipeline_name() {
  local yaml_file="$1"
  python3 -c "
import yaml, sys
data = yaml.safe_load(open('$yaml_file'))
print(data.get('name', 'unnamed'))
"
}

# Count nodes in pipeline
pipeline_node_count() {
  local yaml_file="$1"
  python3 -c "
import yaml
data = yaml.safe_load(open('$yaml_file'))
print(len(data.get('nodes', {})))
"
}

# ---- Helpers: Topological sort + cycle detection ---------------------------

# Run Kahn's algorithm; outputs sorted order or error on cycle
topological_sort() {
  local yaml_file="$1"
  python3 -c "
import yaml, json, sys
from collections import deque

data = yaml.safe_load(open('$yaml_file'))
nodes = data.get('nodes', {})

# Build adjacency and in-degree
in_degree = {name: 0 for name in nodes}
adj = {name: [] for name in nodes}
for name, spec in nodes.items():
    for dep in spec.get('depends_on', []):
        if dep not in nodes:
            print(json.dumps({'error': f\"dependency '{dep}' of '{name}' not found\"}))
            sys.exit(1)
        adj[dep].append(name)
        in_degree[name] += 1

# Kahn's algorithm (BFS)
queue = deque(n for n, d in in_degree.items() if d == 0)
order = []
while queue:
    node = queue.popleft()
    order.append(node)
    for neighbor in adj[node]:
        in_degree[neighbor] -= 1
        if in_degree[neighbor] == 0:
            queue.append(neighbor)

if len(order) != len(nodes):
    cycle_nodes = [n for n in nodes if in_degree[n] > 0]
    print(json.dumps({'error': f\"cycle detected involving: {', '.join(cycle_nodes)}\"}))
    sys.exit(1)

print(json.dumps({'order': order, 'count': len(order)}))
"
}

# ---- Helpers: Validation ---------------------------------------------------

# Validate node types are in allowed set
validate_node_types() {
  local yaml_file="$1"
  local valid_types="$2"
  python3 -c "
import yaml, json, sys

VALID = set('$valid_types'.split())
data = yaml.safe_load(open('$yaml_file'))
nodes = data.get('nodes', {})
invalid = []
for name, spec in nodes.items():
    ntype = spec.get('type', '')
    if ntype not in VALID:
        invalid.append(f'{name} (type={ntype})')
if invalid:
    print(json.dumps({'error': f\"invalid node types: {', '.join(invalid)}\"}))
    sys.exit(1)
print(json.dumps({'ok': True}))
"
}

# ---- Helpers: State tracking -----------------------------------------------

# Initialize pipeline state JSON
init_state() {
  local pipeline_name="$1"
  local run_id="$2"
  local yaml_file="$3"
  mkdir -p "$OUTPUT_DIR"
  python3 << PYEOF
import yaml, json, datetime
data = yaml.safe_load(open('$yaml_file'))
nodes = data.get("nodes", {})
state = {
    "run_id": "$run_id",
    "pipeline": "$pipeline_name",
    "started_at": datetime.datetime.utcnow().isoformat() + "Z",
    "finished_at": None,
    "status": "running",
    "nodes": {}
}
for name in nodes:
    state["nodes"][name] = {
        "status": "pending",
        "type": nodes[name].get("type", ""),
        "started_at": None,
        "finished_at": None,
        "exit_code": None
    }
json.dump(state, open('$STATE_FILE', 'w'), indent=2)
PYEOF
}

# Update a single node's status in state file
update_node_state() {
  local node_name="$1"
  local status="$2"
  local exit_code="${3:-null}"
  python3 << PYEOF
import json, datetime
state = json.load(open('$STATE_FILE'))
node = state["nodes"]["$node_name"]
node["status"] = "$status"
now = datetime.datetime.utcnow().isoformat() + "Z"
if "$status" == "running":
    node["started_at"] = now
elif "$status" in ("completed", "failed", "skipped"):
    node["finished_at"] = now
    node["exit_code"] = $exit_code
state["nodes"]["$node_name"] = node
json.dump(state, open('$STATE_FILE', 'w'), indent=2)
PYEOF
}

# Finalize pipeline state (mark overall status)
finalize_state() {
  local overall_status="$1"
  python3 << PYEOF
import json, datetime
state = json.load(open('$STATE_FILE'))
state["finished_at"] = datetime.datetime.utcnow().isoformat() + "Z"
state["status"] = "$overall_status"
json.dump(state, open('$STATE_FILE', 'w'), indent=2)
PYEOF
}

# ---- Helpers: Node execution -----------------------------------------------

# Execute a scanner node via job-dispatcher.sh
execute_scanner() {
  local node_name="$1"
  local tool="$2"
  local target="$3"
  local dispatcher="$SCRIPT_DIR/job-dispatcher.sh"
  if [ ! -f "$dispatcher" ]; then
    echo "[pipeline] WARNING: job-dispatcher.sh not found, skipping $node_name"
    return 2
  fi
  echo "[pipeline] Running scanner: $tool on $target"
  bash "$dispatcher" --tool "$tool" --target "$target" || return $?
}

# Execute a normalizer node via json-normalizer.sh
execute_normalizer() {
  local node_name="$1"
  local yaml_file="$2"
  local normalizer="$REPO_ROOT/formatters/json-normalizer.sh"
  if [ ! -f "$normalizer" ]; then
    echo "[pipeline] WARNING: json-normalizer.sh not found, skipping $node_name"
    return 2
  fi
  # Collect output files from dependency scanner nodes
  local deps_outputs
  deps_outputs=$(get_dep_outputs "$node_name" "$yaml_file")
  echo "[pipeline] Normalizing outputs from dependencies"
  local output_file
  output_file=$(get_node_output "$node_name" "$yaml_file")
  # Normalize each dependency output individually then merge
  normalize_deps "$normalizer" "$deps_outputs" "$output_file"
}

# Normalize dependency outputs and merge results
normalize_deps() {
  local normalizer="$1"
  local deps_outputs="$2"
  local output_file="$3"
  local tmp_files=""
  for dep_file in $deps_outputs; do
    if [ -f "$dep_file" ]; then
      local tool_name
      tool_name=$(basename "$dep_file" | sed 's/-raw\.json//')
      local tmp_out="$OUTPUT_DIR/${tool_name}-normalized.json"
      bash "$normalizer" --tool "$tool_name" --input "$dep_file" --output "$tmp_out" || true
      [ -n "$tmp_files" ] && tmp_files="$tmp_files,$tmp_out" || tmp_files="$tmp_out"
    fi
  done
  # Merge all normalized files into single output
  if [ -n "$tmp_files" ]; then
    merge_normalized_files "$tmp_files" "$output_file"
  else
    echo '{"findings":[],"summary":{"total":0}}' > "$output_file"
  fi
}

# Merge multiple normalized JSON files into one
merge_normalized_files() {
  local file_list="$1"
  local output="$2"
  python3 -c "
import json
files = '$file_list'.split(',')
all_findings = []
for f in files:
    try:
        data = json.load(open(f.strip()))
        all_findings.extend(data.get('findings', []))
    except: pass
result = {'findings': all_findings, 'summary': {'total': len(all_findings)}}
json.dump(result, open('$output', 'w'), indent=2)
"
}

# Execute a dedup node via dedup-findings.sh
execute_dedup() {
  local node_name="$1"
  local yaml_file="$2"
  local dedup_script="$REPO_ROOT/formatters/dedup-findings.sh"
  if [ ! -f "$dedup_script" ]; then
    echo "[pipeline] WARNING: dedup-findings.sh not found, skipping $node_name"
    return 2
  fi
  local input_file
  input_file=$(get_node_input_file "$node_name" "$yaml_file")
  local output_file
  output_file=$(get_node_output "$node_name" "$yaml_file")
  echo "[pipeline] Deduplicating: $input_file -> $output_file"
  bash "$dedup_script" --inputs "$input_file" --output "$output_file"
}

# Execute a formatter node
execute_formatter() {
  local node_name="$1"
  local yaml_file="$2"
  local input_file
  input_file=$(get_node_input_file "$node_name" "$yaml_file")
  local output_file
  output_file=$(get_node_output "$node_name" "$yaml_file")
  local format
  format=$(get_node_format "$node_name" "$yaml_file")
  local formatter="$REPO_ROOT/formatters/sarif-formatter.sh"
  if [ "$format" = "sarif" ] && [ -f "$formatter" ]; then
    echo "[pipeline] Formatting: $format ($input_file -> $output_file)"
    bash "$formatter" --input "$input_file" --output "$output_file" || return $?
  else
    echo "[pipeline] WARNING: formatter for '$format' not available, copying input"
    cp "$input_file" "$output_file" 2>/dev/null || return 2
  fi
}

# Execute a compliance node (placeholder)
execute_compliance() {
  local node_name="$1"
  local yaml_file="$2"
  echo "[pipeline] WARNING: compliance node '$node_name' is a placeholder, skipping"
  local output_file
  output_file=$(get_node_output "$node_name" "$yaml_file")
  local input_file
  input_file=$(get_node_input_file "$node_name" "$yaml_file")
  # Pass through input as output
  if [ -f "$input_file" ]; then
    cp "$input_file" "$output_file"
  else
    echo '{"findings":[],"compliance":"placeholder"}' > "$output_file"
  fi
}

# ---- Helpers: Node metadata extraction -------------------------------------

# Get output file path for a node
get_node_output() {
  local node_name="$1"
  local yaml_file="$2"
  python3 -c "
import yaml
data = yaml.safe_load(open('$yaml_file'))
node = data['nodes']['$node_name']
out = node.get('outputs', {}).get('file', 'output/${node_name}-output.json')
print(out)
"
}

# Get the input findings file for a node
get_node_input_file() {
  local node_name="$1"
  local yaml_file="$2"
  python3 -c "
import yaml
data = yaml.safe_load(open('$yaml_file'))
node = data['nodes']['$node_name']
inp = node.get('inputs', {}).get('findings', '')
if inp == '\${DEPS_OUTPUTS}':
    deps = node.get('depends_on', [])
    if deps:
        dep_node = data['nodes'][deps[0]]
        print(dep_node.get('outputs', {}).get('file', ''))
    else:
        print('')
else:
    print(inp)
"
}

# Get output files from dependency nodes
get_dep_outputs() {
  local node_name="$1"
  local yaml_file="$2"
  python3 -c "
import yaml
data = yaml.safe_load(open('$yaml_file'))
node = data['nodes']['$node_name']
deps = node.get('depends_on', [])
outputs = []
for dep in deps:
    dep_node = data['nodes'].get(dep, {})
    out = dep_node.get('outputs', {}).get('file', '')
    if out:
        outputs.append(out)
print(' '.join(outputs))
"
}

# Get format for a formatter node
get_node_format() {
  local node_name="$1"
  local yaml_file="$2"
  python3 -c "
import yaml, os
data = yaml.safe_load(open('$yaml_file'))
node = data['nodes']['$node_name']
fmt = node.get('inputs', {}).get('format', 'sarif')
# Resolve env var references like \${OUTPUT_FORMAT:-sarif}
if fmt.startswith('\${') and ':-' in fmt:
    default = fmt.split(':-')[1].rstrip('}')
    var = fmt.split('{')[1].split(':-')[0]
    fmt = os.environ.get(var, default)
print(fmt)
"
}

# Get tool name for a scanner node
get_scanner_tool() {
  local node_name="$1"
  local yaml_file="$2"
  python3 -c "
import yaml
data = yaml.safe_load(open('$yaml_file'))
print(data['nodes']['$node_name'].get('tool', ''))
"
}

# ---- Subcommand: validate --------------------------------------------------

cmd_validate() {
  local yaml_file="$1"
  [ ! -f "$yaml_file" ] && { echo "ERROR: Pipeline file not found: $yaml_file"; exit 1; }

  # Check YAML parses
  local name
  name=$(pipeline_name "$yaml_file")
  local count
  count=$(pipeline_node_count "$yaml_file")

  # Validate node types
  local type_result
  type_result=$(validate_node_types "$yaml_file" "$VALID_NODE_TYPES" 2>&1) || {
    local err
    err=$(echo "$type_result" | python3 -c "import json,sys; print(json.loads(sys.stdin.read()).get('error','unknown'))" 2>/dev/null || echo "$type_result")
    echo "[pipeline] ERROR: $err"
    exit 1
  }

  # Run topological sort (detects cycles + missing deps)
  local topo_result
  topo_result=$(topological_sort "$yaml_file" 2>&1) || {
    local err
    err=$(echo "$topo_result" | python3 -c "import json,sys; print(json.loads(sys.stdin.read()).get('error','unknown'))" 2>/dev/null || echo "$topo_result")
    echo "[pipeline] ERROR: $err"
    exit 1
  }

  echo "[pipeline] Pipeline '$name' is valid ($count nodes, 0 cycles)"
}

# ---- Subcommand: to-json ---------------------------------------------------

cmd_to_json() {
  local yaml_file="$1"
  [ ! -f "$yaml_file" ] && { echo "ERROR: Pipeline file not found: $yaml_file"; exit 1; }
  yaml_to_json "$yaml_file"
}

# ---- Subcommand: list ------------------------------------------------------

cmd_list() {
  echo "[pipeline] Available pipelines in $PIPELINES_DIR:"
  echo ""
  if [ ! -d "$PIPELINES_DIR" ]; then
    echo "  (no pipelines directory found)"
    return
  fi
  for f in "$PIPELINES_DIR"/*.yml; do
    [ ! -f "$f" ] && continue
    local name
    name=$(pipeline_name "$f")
    local count
    count=$(pipeline_node_count "$f")
    local desc
    desc=$(python3 -c "
import yaml
data = yaml.safe_load(open('$f'))
print(data.get('description', ''))
")
    printf "  %-20s %s (%d nodes)\n" "$name" "$desc" "$count"
  done
}

# ---- Subcommand: status ----------------------------------------------------

cmd_status() {
  local run_id="${1:-}"
  local state_path="$STATE_FILE"

  # If --run-id given, look for that specific state file
  if [ -n "$run_id" ]; then
    local alt_path="$OUTPUT_DIR/pipeline-state-${run_id}.json"
    [ -f "$alt_path" ] && state_path="$alt_path"
  fi

  if [ ! -f "$state_path" ]; then
    echo "[pipeline] No pipeline state found at $state_path"
    exit 1
  fi

  python3 << PYEOF
import json
state = json.load(open('$state_path'))
print(f"Pipeline: {state['pipeline']}")
print(f"Run ID:   {state['run_id']}")
print(f"Status:   {state['status']}")
print(f"Started:  {state['started_at']}")
print(f"Finished: {state.get('finished_at', 'N/A')}")
print()
print(f"{'Node':<20} {'Type':<15} {'Status':<12} {'Exit Code'}")
print("-" * 60)
for name, info in state['nodes'].items():
    ec = info.get('exit_code', '-')
    if ec is None:
        ec = '-'
    print(f"{name:<20} {info['type']:<15} {info['status']:<12} {ec}")
PYEOF
}

# ---- Subcommand: run -------------------------------------------------------

cmd_run() {
  local yaml_file="$1"
  shift
  local target="$SCAN_TARGET"
  local out_dir="$OUTPUT_DIR"

  while [[ $# -gt 0 ]]; do
    case $1 in
      --target) target="$2"; shift 2 ;;
      --output-dir) out_dir="$2"; shift 2 ;;
      *) echo "Unknown option: $1"; exit 1 ;;
    esac
  done

  OUTPUT_DIR="$out_dir"
  STATE_FILE="$OUTPUT_DIR/pipeline-state.json"
  SCAN_TARGET="$target"

  [ ! -f "$yaml_file" ] && { echo "ERROR: Pipeline file not found: $yaml_file"; exit 1; }

  # Validate first
  cmd_validate "$yaml_file" || exit 1

  # Get execution order
  local topo_json
  topo_json=$(topological_sort "$yaml_file")
  local order
  order=$(echo "$topo_json" | python3 -c "import json,sys; print(' '.join(json.loads(sys.stdin.read())['order']))")

  # Initialize state
  local name
  name=$(pipeline_name "$yaml_file")
  local run_id="run-$(date +%Y%m%d-%H%M%S)-$$"
  init_state "$name" "$run_id" "$yaml_file"
  mkdir -p "$OUTPUT_DIR"

  echo "[pipeline] Executing pipeline '$name' (run: $run_id)"
  echo "[pipeline] Execution order: $order"
  echo ""

  local overall="completed"
  execute_nodes_in_order "$order" "$yaml_file" || overall="failed"

  finalize_state "$overall"
  echo ""
  echo "[pipeline] Pipeline $overall (run: $run_id)"
  echo "[pipeline] State: $STATE_FILE"
}

# Execute nodes in topological order
execute_nodes_in_order() {
  local order="$1"
  local yaml_file="$2"
  local had_failure=0

  for node_name in $order; do
    local node_type
    node_type=$(python3 -c "
import yaml
data = yaml.safe_load(open('$yaml_file'))
print(data['nodes']['$node_name'].get('type', ''))
")
    execute_single_node "$node_name" "$node_type" "$yaml_file" || had_failure=1
  done
  return $had_failure
}

# Execute one node, update state, handle errors
execute_single_node() {
  local node_name="$1"
  local node_type="$2"
  local yaml_file="$3"
  local exit_code=0

  update_node_state "$node_name" "running"
  echo "[pipeline] >> $node_name ($node_type)"

  dispatch_node "$node_name" "$node_type" "$yaml_file" || exit_code=$?

  if [ "$exit_code" -eq 2 ]; then
    update_node_state "$node_name" "skipped" "0"
    echo "[pipeline] << $node_name: skipped"
  elif [ "$exit_code" -ne 0 ]; then
    update_node_state "$node_name" "failed" "$exit_code"
    echo "[pipeline] << $node_name: FAILED (exit $exit_code)"
    return 1
  else
    update_node_state "$node_name" "completed" "0"
    echo "[pipeline] << $node_name: completed"
  fi
  return 0
}

# Route node to appropriate executor by type
dispatch_node() {
  local node_name="$1"
  local node_type="$2"
  local yaml_file="$3"

  case "$node_type" in
    scanner)
      local tool
      tool=$(get_scanner_tool "$node_name" "$yaml_file")
      execute_scanner "$node_name" "$tool" "$SCAN_TARGET"
      ;;
    normalizer)
      execute_normalizer "$node_name" "$yaml_file"
      ;;
    dedup|deduplicator)
      execute_dedup "$node_name" "$yaml_file"
      ;;
    formatter)
      execute_formatter "$node_name" "$yaml_file"
      ;;
    compliance)
      execute_compliance "$node_name" "$yaml_file"
      ;;
    enricher|gate|storage)
      echo "[pipeline] WARNING: node type '$node_type' is a placeholder, skipping"
      return 2
      ;;
    *)
      echo "[pipeline] ERROR: unknown node type '$node_type'"
      return 1
      ;;
  esac
}

# ---- Subcommand: rerun -----------------------------------------------------

cmd_rerun() {
  local yaml_file="$1"
  shift
  local node_name=""

  while [[ $# -gt 0 ]]; do
    case $1 in
      --node) node_name="$2"; shift 2 ;;
      *) echo "Unknown option: $1"; exit 1 ;;
    esac
  done

  [ -z "$node_name" ] && { echo "ERROR: --node is required"; exit 1; }
  [ ! -f "$yaml_file" ] && { echo "ERROR: Pipeline file not found: $yaml_file"; exit 1; }

  # Verify node exists
  local node_type
  node_type=$(python3 -c "
import yaml, sys
data = yaml.safe_load(open('$yaml_file'))
node = data.get('nodes', {}).get('$node_name')
if node is None:
    print('ERROR: node not found', file=sys.stderr)
    sys.exit(1)
print(node.get('type', ''))
") || { echo "ERROR: node '$node_name' not found in pipeline"; exit 1; }

  echo "[pipeline] Re-running node: $node_name ($node_type)"
  mkdir -p "$OUTPUT_DIR"

  # Update state if state file exists
  if [ -f "$STATE_FILE" ]; then
    update_node_state "$node_name" "running"
  fi

  local exit_code=0
  dispatch_node "$node_name" "$node_type" "$yaml_file" || exit_code=$?

  if [ -f "$STATE_FILE" ]; then
    local status="completed"
    [ "$exit_code" -eq 2 ] && status="skipped"
    [ "$exit_code" -gt 2 ] && status="failed"
    [ "$exit_code" -eq 1 ] && status="failed"
    update_node_state "$node_name" "$status" "$exit_code"
  fi

  echo "[pipeline] Node '$node_name' finished (exit: $exit_code)"
  return $exit_code
}

# ---- Main dispatcher -------------------------------------------------------

usage() {
  cat << 'EOF'
DevSecOps AI Team -- DAG Pipeline Engine

Usage:
  pipeline-engine.sh validate <pipeline.yml>    Validate pipeline (cycles, types, deps)
  pipeline-engine.sh run <pipeline.yml> [opts]  Execute pipeline
  pipeline-engine.sh to-json <pipeline.yml>     Convert YAML to JSON
  pipeline-engine.sh list                       List available pipelines
  pipeline-engine.sh status [--run-id ID]       Show pipeline run status
  pipeline-engine.sh rerun <pipeline.yml> --node NAME  Re-execute single node

Run options:
  --target <path>       Scan target (default: $SCAN_TARGET or .)
  --output-dir <dir>    Output directory (default: ./output)
EOF
  exit 1
}

[ $# -lt 1 ] && usage

COMMAND="$1"
shift

case "$COMMAND" in
  validate)
    [ $# -lt 1 ] && { echo "ERROR: validate requires a pipeline YAML file"; exit 1; }
    cmd_validate "$1"
    ;;
  run)
    [ $# -lt 1 ] && { echo "ERROR: run requires a pipeline YAML file"; exit 1; }
    cmd_run "$@"
    ;;
  to-json)
    [ $# -lt 1 ] && { echo "ERROR: to-json requires a pipeline YAML file"; exit 1; }
    cmd_to_json "$1"
    ;;
  list)
    cmd_list
    ;;
  status)
    local_run_id=""
    while [[ $# -gt 0 ]]; do
      case $1 in
        --run-id) local_run_id="$2"; shift 2 ;;
        *) shift ;;
      esac
    done
    cmd_status "$local_run_id"
    ;;
  rerun)
    [ $# -lt 1 ] && { echo "ERROR: rerun requires a pipeline YAML file"; exit 1; }
    cmd_rerun "$@"
    ;;
  *)
    echo "ERROR: Unknown command: $COMMAND"
    usage
    ;;
esac
