#!/bin/bash

# Required parameters
TFE_TOKEN="${TFE_TOKEN:-}"  # Use environment variable or set manually
ORG_NAME="${ORG_NAME:-}"    # Terraform Enterprise Organization name
WORKSPACE_NAME="cloud-broker-management-zone"
COMMIT_SHA="$1"  # Commit SHA passed as first argument

# Logging and error handling
log() {
    echo "[$(date +'%Y-%m-%d %H:%M:%S')] $*"
}

error_exit() {
    log "ERROR: $*"
    exit 1
}

# Validate inputs
[ -z "$TFE_TOKEN" ] && error_exit "Terraform Enterprise token is required. Set TFE_TOKEN environment variable."
[ -z "$ORG_NAME" ] && error_exit "Organization name is required. Set ORG_NAME environment variable."
[ -z "$COMMIT_SHA" ] && error_exit "Commit SHA is required as first argument"

# Function to get workspace ID
get_workspace_id() {
    local workspace_response=$(curl -s \
        --header "Authorization: Bearer $TFE_TOKEN" \
        --header "Content-Type: application/vnd.api+json" \
        "https://app.terraform.io/api/v2/organizations/$ORG_NAME/workspaces/$WORKSPACE_NAME")
    
    local workspace_id=$(echo "$workspace_response" | jq -r '.data.id')
    
    [ -z "$workspace_id" ] || [ "$workspace_id" == "null" ] && 
        error_exit "Could not fetch workspace ID for $WORKSPACE_NAME"
    
    echo "$workspace_id"
}

# Function to get run based on commit SHA
get_run_for_commit() {
    local workspace_id="$1"
    local runs_response=$(curl -s \
        --header "Authorization: Bearer $TFE_TOKEN" \
        --header "Content-Type: application/vnd.api+json" \
        "https://app.terraform.io/api/v2/workspaces/$workspace_id/runs?filter%5Bvcs-sha%5D=$COMMIT_SHA")
    
    local run_id=$(echo "$runs_response" | jq -r '.data[0].id')
    
    [ -z "$run_id" ] || [ "$run_id" == "null" ] && 
        error_exit "No run found for commit SHA: $COMMIT_SHA"
    
    echo "$run_id"
}

# Continuous monitoring function
monitor_run() {
    local run_id="$1"
    local max_attempts=180  # 30 minutes (180 * 10s)
    local attempt=0

    while [ $attempt -lt $max_attempts ]; do
        # Fetch current run status
        local run_details=$(curl -s \
            --header "Authorization: Bearer $TFE_TOKEN" \
            --header "Content-Type: application/vnd.api+json" \
            "https://app.terraform.io/api/v2/runs/$run_id")
        
        local status=$(echo "$run_details" | jq -r '.data.attributes.status')
        local status_description=$(echo "$run_details" | jq -r '.data.attributes["status-description"]')

        log "Current Run Status: $status - $status_description"

        # Check for final states
        case "$status" in
            "applied")
                log "Run successfully applied"
                return 0
                ;;
            "errored"|"force_canceled")
                log "Run failed with status: $status"
                error_exit "Terraform run failed: $status_description"
                ;;
            "pending"|"planning"|"applying"|"confirmed")
                # Continue monitoring
                log "Run in progress. Waiting..."
                sleep 10
                ((attempt++))
                ;;
            *)
                log "Unexpected status: $status"
                sleep 10
                ((attempt++))
                ;;
        esac
    done

    # Timeout if run doesn't complete
    error_exit "Monitoring timed out after 30 minutes"
}

# Main execution
main() {
    log "Starting Terraform run monitoring for commit SHA: $COMMIT_SHA"

    # Get workspace and run IDs
    local workspace_id=$(get_workspace_id)
    local run_id=$(get_run_for_commit "$workspace_id")

    # Monitor the run
    monitor_run "$run_id"
}

# Execute main function
main
