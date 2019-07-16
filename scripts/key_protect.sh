#!/bin/bash

## ----------------------------------------------------------------------------
#
# Key Protect API:
#
###
#
# kp instance management:
#
#   create_vault_instance                   :: $KP_SERVICE_NAME $REGION
#   retrieve_vault_instance                 :: $KP_SERVICE_NAME $KP_GUID $REGION
#   update_vault_instance                   :: $KP_SERVICE_NAME $KP_GUID $REGION
#   delete_vault_instance                   :: $KP_SERVICE_NAME $KP_GUID $REGION
#
###
#
# iam cross authenticate an integrated service with keyprotect:
#
#   assign_iam_writer_access_for_service    :: $KP_SERVICE_NAME $KP_GUID $SERVICE_ID
#
###
#
# key management:
#
#   get_root_key                            :: $KP_SERVICE_NAME $KP_GUID $REGION $KP_ACCESS_TOKEN $MY_KEY_MATERIAL
#   get_standard_key                        :: $KP_SERVICE_NAME $KP_GUID $REGION $KP_ACCESS_TOKEN $KP_GUID $MY_KEY_MATERIAL
#   delete_key                              :: $KP_SERVICE_NAME $KP_GUID $REGION
#
## ----------------------------------------------------------------------------

# create an instance of the secrets vault...
function create_vault_instance {
    ##
    # keyprotect assumed default at the moment but
    # optional hashicorp vault provider should be
    # handled/tested here too...
    
    section "create_vault_instance: $1"
    
    #
    # create_vault_instance service-name region
    #
    # eg: create_vault_instance secure-file-storage-kms region
    ##
    if check_exists "$(ibmcloud resource service-instance $1 2>&1)"; then
        echo "Key Protect service named '$1' already exists"
    else
        ibmcloud resource service-instance-create $1 kms tiered-pricing $2 || exit 1
    fi

    KP_INSTANCE_ID=$(get_instance_id $1)
    KP_GUID=$(get_guid $1)
    echo "KP_INSTANCE_ID=$KP_INSTANCE_ID"
    echo "KP_GUID=$KP_GUID"
    check_value "$KP_INSTANCE_ID"
    check_value "$KP_GUID"

    if check_exists "$(ibmcloud resource service-key $1-acckey-$KP_GUID 2>&1)"; then
        echo "Key Protect key already exists"
    else
        ibmcloud resource service-key-create $1-acckey-$KP_GUID Manager \
            --instance-id "$KP_INSTANCE_ID" || exit 1
    fi
}

## ----------------------------------------------------------------------------

function assign_iam_writer_access_for_service {
    ##
    # assign_iam_writer_access_for_service $SERVICE_ID $KP_SERVICE_NAME $KP_GUID
    #
    
    section "assign_iam_writer_access_for_service: $KP_SERVICE_NAME"
    
    EXISTING_POLICIES=$(ibmcloud iam service-policies $SERVICE_ID --output json)
    echo "EXISTING_POLICIES=$EXISTING_POLICIES"
    check_value "$EXISTING_POLICIES"

    # Create a policy to make serviceID a writer for Key Protect
    if echo "$EXISTING_POLICIES" | \
    jq -e -r 'select(.[].resources[].attributes[].name=="serviceInstance" and .[].resources[].attributes[].value=="'$KP_GUID'" and .[].roles[].display_name=="Writer")' > /dev/null; then
        echo "Writer policy on Key Protect already exist for the Service ID"
    else
        ibmcloud iam service-policy-create $SERVICE_ID --roles Writer --service-name kms --service-instance $KP_GUID --force
    fi

    KP_CREDENTIALS=$(ibmcloud resource service-key $KP_SERVICE_NAME-acckey-$KP_GUID --output JSON)
    KP_IAM_APIKEY=$(echo "$KP_CREDENTIALS" | jq -r .[0].credentials.apikey)
    KP_ACCESS_TOKEN=$(get_access_token $KP_IAM_APIKEY)
}

## ----------------------------------------------------------------------------

function generate_root_key {
    ##
    # generate_root_key $KP_SERVICE_NAME $REGION $KP_ACCESS_TOKEN $KP_GUID
    #
    
    section "generate_root_key: $KP_SERVICE_NAME"

    KP_MANAGEMENT_URL="https://$REGION.kms.cloud.ibm.com/api/v2/keys"

    # create a root key based on the @scripts/root-enckey.json
    # definition if it does not exist...
    KP_KEYS=$(curl -s $KP_MANAGEMENT_URL \
    --header "Authorization: Bearer $KP_ACCESS_TOKEN" \
    --header "Bluemix-Instance: $KP_GUID")
    check_value "$KP_KEYS"

    if echo $KP_KEYS | jq -e -r '.resources[] | select(.name=="$KP_SERVICE_NAME-root-enckey")' > /dev/null; then
        echo "Root key already exists for service '$KP_SERVICE_NAME'"
    else
        KP_KEYS=$(curl -s -X POST $KP_MANAGEMENT_URL \
            --header "Authorization: Bearer $KP_ACCESS_TOKEN" \
            --header "Bluemix-Instance: $KP_GUID" \
            --header "Content-Type: application/vnd.ibm.kms.key+json" -d @scripts/root-enckey.json)
    fi

    ROOT_KEY_CRN=$(echo $KP_KEYS | jq -e -r '.resources[] | select(.name=="$KP_SERVICE_NAME-root-enckey") | .crn')
    echo "ROOT_KEY_CRN=$ROOT_KEY_CRN"
}

## ----------------------------------------------------------------------------

function generate_standard_key {
    ##
    # generate_standard_key $KP_SERVICE_NAME $REGION $KP_ACCESS_TOKEN $KP_GUID
    #
    
    section "generate_standard_key: $KP_SERVICE_NAME"

    KP_MANAGEMENT_URL="https://$REGION.kms.cloud.ibm.com/api/v2/keys"

    # Create standard key if it does not exist
    KP_KEYS=$(curl -s $KP_MANAGEMENT_URL \
    --header "Authorization: Bearer $KP_ACCESS_TOKEN" \
    --header "Bluemix-Instance: $KP_GUID")
    check_value "$KP_KEYS"

    if echo $KP_KEYS | jq -e -r '.resources[] | select(.name=="$KP_SERVICE_NAME-standard-enckey")' > /dev/null; then
        echo "Standard key already exists for service '$KP_SERVICE_NAME'"
    else
        KP_KEYS=$(curl -s -X POST $KP_MANAGEMENT_URL \
            --header "Authorization: Bearer $KP_ACCESS_TOKEN" \
            --header "Bluemix-Instance: $KP_GUID" \
            --header "Content-Type: application/vnd.ibm.kms.key+json" -d @scripts/standard-enckey.json)
    fi

    STANDARD_KEY_CRN=$(echo $KP_KEYS | jq -e -r '.resources[] | select(.name=="$KP_SERVICE_NAME-standard-enckey") | .crn')
    echo "STANDARD_KEY_CRN=$STANDARD_KEY_CRN"
}

## ----------------------------------------------------------------------------

function retrieve_vault_instance {
    ##
    # 
    ##
    
    section "retrieve_vault_instance: $KP_SERVICE_NAME"
    
    #
    # retrieve_vault_instance service-name service_id /*integrated service id for writer/iam access*/
    #
    # eg: retrieve_vault_instance secure-file-storage-kms region
    ##
    if check_exists "$(ibmcloud resource service-instance $KP_SERVICE_NAME 2>&1)"; then
        echo "Key Protect service named '$KP_SERVICE_NAME' already exists"
    else
        ibmcloud resource service-instance-create $KP_SERVICE_NAME kms tiered-pricing $REGION || exit 1
    fi

    KP_INSTANCE_ID=$(get_instance_id $KP_SERVICE_NAME)
    KP_GUID=$(get_guid $KP_SERVICE_NAME)
    echo "KP_INSTANCE_ID=$KP_INSTANCE_ID"
    echo "KP_GUID=$KP_GUID"
    check_value "$KP_INSTANCE_ID"
    check_value "$KP_GUID"

    if check_exists "$(ibmcloud resource service-key $KP_SERVICE_NAME-acckey-$KP_GUID 2>&1)"; then
        echo "Key Protect key already exists"
    else
        ibmcloud resource service-key-create $KP_SERVICE_NAME-acckey-$KP_GUID Manager \
            --instance-id "$KP_INSTANCE_ID" || exit 1
    fi
}

## ----------------------------------------------------------------------------

function update_vault_instance {
    ##
    # 
    ##
    
    section "update_vault_instance: $KP_SERVICE_NAME"
}

## ----------------------------------------------------------------------------

function delete_vault_instance {
    ##
    # 
    ##
    
    section "delete_vault_instance: $KP_SERVICE_NAME"
}

## ----------------------------------------------------------------------------

# returns an IAM access token given an API key
function get_access_token {
  IAM_ACCESS_TOKEN_FULL=$(curl -s -k -X POST \
  --header "Content-Type: application/x-www-form-urlencoded" \
  --header "Accept: application/json" \
  --data-urlencode "grant_type=urn:ibm:params:oauth:grant-type:apikey" \
  --data-urlencode "apikey=$1" \
  "https://iam.cloud.ibm.com/identity/token")
  IAM_ACCESS_TOKEN=$(echo "$IAM_ACCESS_TOKEN_FULL" | \
    grep -Eo '"access_token":"[^"]+"' | \
    awk '{split($0,a,":"); print a[2]}' | \
    tr -d \")
  echo $IAM_ACCESS_TOKEN
}

## ----------------------------------------------------------------------------

# returns a service CRN given a service name
function get_instance_id {
  OUTPUT=$(ibmcloud resource service-instance --output JSON $1)
  if (echo $OUTPUT | grep -q "crn:v1" >/dev/null); then
    echo $OUTPUT | jq -r .[0].id
  else
    echo "Failed to get instance ID: $OUTPUT"
    exit 2
  fi
}

## ----------------------------------------------------------------------------

# returns a service GUID given a service name
function get_guid {
  OUTPUT=$(ibmcloud resource service-instance --id $1)
  if (echo $OUTPUT | grep -q "crn:v1" >/dev/null); then
    echo $OUTPUT | awk -F ":" '{print $8}'
  else
    echo "Failed to get GUID: $OUTPUT"
    exit 2
  fi
}

## ----------------------------------------------------------------------------

# outputs a separator banner
function section {
  echo
  echo "####################################################################"
  echo "#"
  echo "# $1"
  echo "#"
  echo "####################################################################"
  echo
}

## ----------------------------------------------------------------------------

function check_exists {
  if echo "$1" | grep -q "not found"; then
    return 1
  fi
  if echo "$1" | grep -q "crn:v1"; then
    return 0
  fi
  echo "Failed to check if object exists: $1"
  exit 2
}

## ----------------------------------------------------------------------------

function check_value {
  if [ -z "$1" ]; then
    exit 1
  fi

  if echo $1 | grep -q -i "failed"; then
    exit 2
  fi
}

## ----------------------------------------------------------------------------
