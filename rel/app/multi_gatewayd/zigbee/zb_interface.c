/*
 * Copyright 2017 Ayla Networks, Inc.  All rights reserved.
 *
 * Use of the accompanying software is permitted only in accordance
 * with and subject to the terms of the Software License Agreement
 * with Ayla Networks, Inc., a copy of which can be obtained from
 * Ayla Networks, Inc.
 */

#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>

#include "ember_stack_include.h"

#include "ember/af-structs.h"
#include "ember/attribute-id.h"
#include "ember/attribute-type.h"
#include "ember/att-storage.h"
#include "ember/callback.h"
#include "ember/cluster-id.h"
#include "ember/command-id.h"
#include "ember/enums.h"
#include "ember/print-cluster.h"


#include <ayla/log.h>
#include <ayla/assert.h>

#define u8 uint8_t

#include <app/props.h>
#include <ayla/gateway_interface.h>
#include <app/gateway.h>

#include "node.h"
#include "zb_interface.h"
#include "appd_interface.h"
#include "appd_interface_node.h"




#define BAUD_RATE 115200
#define TRACE_ALL (TRACE_FRAMES_BASIC | TRACE_FRAMES_VERBOSE \
			| TRACE_EVENTS | TRACE_EZSP | TRACE_EZSP_VERBOSE)
#define SERIAL_PATH "/dev/ttyUSB0"


#define COMMAND_ID_MASK  0x0000000F
#define MOVE_MODE_MASK   0x000000F0
#define LEVEL_RATE_MASK  0x0000FF00
#define TRANS_TIME_MASK  0xFFFF0000



/* when this is set to true it means the NCP has reported a serious error
 and the host needs to reset and re-init the NCP */
static bool ncpNeedsResetAndInit;



/*
 * Send simple descriptor request to node
 */
int zb_send_simple_request(uint16_t node_id)
{
	EmberStatus status;
	status = emberSimpleDescriptorRequest(node_id, 1,
	    EMBER_APS_OPTION_NONE);
	if (status != EMBER_SUCCESS) {
		log_err("emberSimpleDescriptorRequest for node"
		    " 0x%04X ret %d", node_id, status);
		return -1;
	} else {
		log_debug("emberSimpleDescriptorRequest for node"
		    " 0x%04X success", node_id);
	}

	return 0;
}

/*
 * Send power descriptor request to node
 */
int zb_send_power_request(uint16_t node_id)
{
	EmberStatus status;

	status = emberPowerDescriptorRequest(node_id, EMBER_APS_OPTION_NONE);
	if (status != EMBER_SUCCESS) {
		log_err("emberPowerDescriptorRequest for node_id=0x%04X"
		    " ret %d", node_id, status);
		return -1;
	} else {
		log_debug("emberPowerDescriptorRequest for node_id=0x%04X"
		    " success", node_id);
	}

	return 0;
}

/*
 * Send leave request to node
 */
int zb_send_leave_request(uint16_t node_id)
{
	EmberEUI64 node_eui = { 0, 0, 0, 0, 0, 0, 0, 0 };
	uint8_t flag = 0;
	EmberApsOption options = EMBER_APS_OPTION_NONE;
	EmberStatus status;

	flag |= EMBER_ZIGBEE_LEAVE_AND_REMOVE_CHILDREN;
	/* flag |= EMBER_ZIGBEE_LEAVE_AND_REJOIN; */

	status = emberLeaveRequest(node_id, node_eui, flag, options);
	if (status != EMBER_SUCCESS) {
		log_err("emberLeaveRequest for node_id=0x%04X"
		    " ret %d", node_id, status);
		return -1;
	} else {
		log_debug("emberLeaveRequest for node_id=0x%04X"
		    " success", node_id);
	}

	return 0;
}

/*
 * Send network address request to node
 */
int zb_send_net_addr_request(EmberEUI64 node_eui)
{
	EmberStatus status;
	status = emberNetworkAddressRequest(node_eui, false, 0);
	if (status != EMBER_SUCCESS) {
		log_err("emberNetworkAddressRequest ret %d", status);
		return -1;
	} else {
		log_debug("emberNetworkAddressRequest ret success");
	}
	return 0;
}

/*
 * Send IEEE address request to node
 */
int zb_send_ieee_addr_request(uint16_t node_id)
{
	EmberApsOption options = EMBER_APS_OPTION_NONE;
	EmberStatus status;
	status = emberIeeeAddressRequest(node_id, false, 0, options);
	if (status != EMBER_SUCCESS) {
		log_err("emberIeeeAddressRequest ret %d", status);
		return -1;
	} else {
		log_debug("emberIeeeAddressRequest ret success");
	}
	return 0;
}

/*
 * Send onoff request to node
 */
int zb_send_onoff_request(uint16_t node_id, bool onoff)
{
	EmberStatus status;

	if (onoff) {
		emberAfFillCommandOnOffClusterOn();
	} else {
		emberAfFillCommandOnOffClusterOff();
	}
	emberAfSetCommandEndpoints(1, 1);

	status = emberAfSendCommandUnicast(EMBER_OUTGOING_DIRECT, node_id);
	if (status == EMBER_SUCCESS) {
		log_debug("emberAfSendCommandUnicast node_id=0x%04X success"
		    " 0x%X", node_id, status);
		return 0;
	} else {
		log_err("emberAfSendCommandUnicast node_id=0x%04X failure"
		    " 0x%X", node_id, status);
		return -1;
	}
}

/*
 * Send level control request to node
 */
int zb_send_level_control_request(uint16_t node_id, int level)
{
	uint8_t commandId = (uint8_t)(level & COMMAND_ID_MASK);
	uint8_t moveMode = (uint8_t)((level & MOVE_MODE_MASK) >> 4);
	uint8_t levelRate = (uint8_t)((level & LEVEL_RATE_MASK) >> 8);
	uint16_t transTime = (uint16_t)((level & TRANS_TIME_MASK) >> 16);
	EmberStatus status;

	switch (commandId) {
	case ZCL_MOVE_TO_LEVEL_COMMAND_ID:
		log_debug("Send level control command: mv-to-level");
		emberAfFillCommandLevelControlClusterMoveToLevel(
		    level, transTime);
		break;
	case ZCL_MOVE_COMMAND_ID:
		log_debug("Send level control command: move");
		emberAfFillCommandLevelControlClusterMove(
		    moveMode, levelRate);
		break;
	case ZCL_STEP_COMMAND_ID:
		log_debug("Send level control command: step");
		emberAfFillCommandLevelControlClusterStep(
		    moveMode, levelRate, transTime);
		break;
	case ZCL_STOP_COMMAND_ID:
		log_debug("Send level control command: stop");
		emberAfFillCommandLevelControlClusterStop();
		break;
	case ZCL_MOVE_TO_LEVEL_WITH_ON_OFF_COMMAND_ID:
		log_debug("Send level control command: o-mv-to-level");
		emberAfFillCommandLevelControlClusterMoveToLevelWithOnOff(
		    levelRate, transTime);
		break;
	case ZCL_MOVE_WITH_ON_OFF_COMMAND_ID:
		log_debug("Send level control command: o-move");
		emberAfFillCommandLevelControlClusterMoveWithOnOff(
		    moveMode, levelRate);
		break;
	case ZCL_STEP_WITH_ON_OFF_COMMAND_ID:
		log_debug("Send level control command: o-step");
		emberAfFillCommandLevelControlClusterStepWithOnOff(
		    moveMode, levelRate, transTime);
		break;
	case ZCL_STOP_WITH_ON_OFF_COMMAND_ID:
		log_debug("Send level control command: o-stop");
		emberAfFillCommandLevelControlClusterStopWithOnOff();
		break;
	default:
		log_err("No level control command 0x%02X", commandId);
		return -1;
	}

	emberAfSetCommandEndpoints(1, 1);

	status = emberAfSendCommandUnicast(EMBER_OUTGOING_DIRECT, node_id);
	if (status == EMBER_SUCCESS) {
		log_debug("emberAfSendCommandUnicast node_id=0x%04X success"
		    " 0x%X", node_id, status);
		return 0;
	} else {
		log_err("emberAfSendCommandUnicast node_id=0x%04X failure"
		    " 0x%X", node_id, status);
		return -1;
	}
}

/*
 * Send read attribute to node
 */
static int zb_send_read_attribute_request(uint16_t node_id,
			uint16_t cluster_id, uint16_t attribute_id)
{
	EmberStatus status;

	emberAfFillCommandGlobalClientToServerReadAttributes(
	    cluster_id, &attribute_id, sizeof(uint16_t));

	emberAfSetCommandEndpoints(1, 1);

	status = emberAfSendCommandUnicast(EMBER_OUTGOING_DIRECT, node_id);
	if (status == EMBER_SUCCESS) {
		log_debug("emberAfSendCommandUnicast node_id=0x%04X success"
		    " 0x%X", node_id, status);
		return 0;
	} else {
		log_err("emberAfSendCommandUnicast node_id=0x%04X failure"
		    " 0x%X", node_id, status);
		return -1;
	}
}

/*
 * Send power source request to node
 */
int zb_send_power_source_request(uint16_t node_id)
{
	return zb_send_read_attribute_request(node_id,
	    ZCL_BASIC_CLUSTER_ID, ZCL_POWER_SOURCE_ATTRIBUTE_ID);
}

/*
 * Send model identifier request to node
 */
int zb_send_model_identifier_request(uint16_t node_id)
{
	return zb_send_read_attribute_request(node_id,
	    ZCL_BASIC_CLUSTER_ID, ZCL_MODEL_IDENTIFIER_ATTRIBUTE_ID);
}

/*
 * Send read zone state request to node
 */
int zb_send_read_zone_state_request(uint16_t node_id)
{
	return zb_send_read_attribute_request(node_id,
	    ZCL_IAS_ZONE_CLUSTER_ID, ZCL_ZONE_STATE_ATTRIBUTE_ID);
}

/*
 * Send write attribute to node
 */
static int zb_send_write_attribute_request(uint16_t node_id,
			uint16_t cluster_id,
			uint8_t *write_attr, uint16_t write_len)
{
	EmberStatus status;

	emberAfFillCommandGlobalClientToServerWriteAttributes(
	    cluster_id, write_attr, write_len);

	emberAfSetCommandEndpoints(1, 1);

	status = emberAfSendCommandUnicast(EMBER_OUTGOING_DIRECT, node_id);
	if (status == EMBER_SUCCESS) {
		log_debug("emberAfSendCommandUnicast node_id=0x%04X success"
		    " 0x%X", node_id, status);
		return 0;
	} else {
		log_err("emberAfSendCommandUnicast node_id=0x%04X failure"
		    " 0x%X", node_id, status);
		return -1;
	}
}

/*
 * Send write CIE address request to node
 */
int zb_send_write_cie_request(uint16_t node_id)
{
	uint8_t write_attr[] = {
		((uint8_t)((ZCL_IAS_CIE_ADDRESS_ATTRIBUTE_ID) & 0xFF)),
		((uint8_t)((ZCL_IAS_CIE_ADDRESS_ATTRIBUTE_ID >> 8) & 0xFF)),
		((uint8_t)(ZCL_IEEE_ADDRESS_ATTRIBUTE_TYPE)),
		0, 0, 0, 0, 0, 0, 0, 0
	};

	emberAfGetEui64(&write_attr[3]);

	return zb_send_write_attribute_request(node_id,
	    ZCL_IAS_ZONE_CLUSTER_ID, write_attr, sizeof(write_attr));
}

/*
 * Send write 8 bits data attribute request to node
 */
int zb_send_write_8bit_attr_request(uint16_t node_id, uint16_t cluster_id,
			uint16_t attr_id, uint8_t attr_type, uint8_t value)
{
	uint8_t write_attr[] = {
		((uint8_t)(attr_id & 0xFF)),
		((uint8_t)((attr_id >> 8) & 0xFF)),
		attr_type,
		value
	};

	return zb_send_write_attribute_request(node_id, cluster_id,
	    write_attr, sizeof(write_attr));
}

/*
 * Send write 16 bits data attribute request to node
 */
int zb_send_write_16bit_attr_request(uint16_t node_id, uint16_t cluster_id,
			uint16_t attr_id, uint8_t attr_type, uint16_t value)
{
	uint8_t write_attr[] = {
		((uint8_t)((attr_id) & 0xFF)),
		((uint8_t)((attr_id >> 8) & 0xFF)),
		attr_type,
		((uint8_t)((value) & 0xFF)),
		((uint8_t)((value >> 8) & 0xFF)),
	};

	return zb_send_write_attribute_request(node_id, cluster_id,
	    write_attr, sizeof(write_attr));
}

/*
 * Send enroll response to node
 */
int zb_send_enroll_response(uint16_t node_id,
			uint8_t resp_code, uint8_t zone_id)
{
	EmberStatus status;

	emberAfFillCommandIasZoneClusterZoneEnrollResponse(
	    resp_code, zone_id);

	emberAfSetCommandEndpoints(1, 1);

	status = emberAfSendCommandUnicast(EMBER_OUTGOING_DIRECT, node_id);
	if (status == EMBER_SUCCESS) {
		log_debug("emberAfSendCommandUnicast node_id=0x%04X success"
		    " 0x%X", node_id, status);
		return 0;
	} else {
		log_err("emberAfSendCommandUnicast node_id=0x%04X failure"
		    " 0x%X", node_id, status);
		return -1;
	}
}

/*
 * Send default response to node
 */
static int zb_send_default_response(uint16_t node_id, uint16_t cluster_id,
			uint8_t command_id, uint8_t status_code)
{
	EmberStatus status;

	emberAfFillCommandGlobalClientToServerDefaultResponse(
		cluster_id, command_id, status_code);

	emberAfSetCommandEndpoints(1, 1);

	status = emberAfSendCommandUnicast(EMBER_OUTGOING_DIRECT, node_id);
	if (status == EMBER_SUCCESS) {
		log_debug("emberAfSendCommandUnicast node_id=0x%04X success"
		    " 0x%X", node_id, status);
		return 0;
	} else {
		log_err("emberAfSendCommandUnicast node_id=0x%04X failure"
		    " 0x%X", node_id, status);
		return -1;
	}
}

/*
 * Send status change notification response to node
 */
int zb_send_notification_response(uint16_t node_id)
{
	return zb_send_default_response(node_id,
	    ZCL_IAS_ZONE_CLUSTER_ID,
	    ZCL_ZONE_STATUS_CHANGE_NOTIFICATION_COMMAND_ID,
	    EMBER_ZCL_STATUS_SUCCESS);
}

/*
 * Send match response to node
 */
int zb_send_match_response(uint16_t node_id, uint8_t *content, uint8_t length)
{
	EmberApsFrame apsFrame;
	EmberStatus status;

	apsFrame.sourceEndpoint = EMBER_ZDO_ENDPOINT;
	apsFrame.destinationEndpoint = EMBER_ZDO_ENDPOINT;
	apsFrame.clusterId = MATCH_DESCRIPTORS_RESPONSE;
	apsFrame.profileId = EMBER_ZDO_PROFILE_ID;
	apsFrame.options = EMBER_APS_OPTION_NONE;

	status = ezspSendUnicast(EMBER_OUTGOING_DIRECT,
				node_id,
				&apsFrame,
				content[0],
				length,
				content,
				&apsFrame.sequence);
	if (status == EMBER_SUCCESS) {
		log_debug("ezspSendUnicast node_id=0x%04X success 0x%X"
			", returned seq_no=%d",
		    node_id, status, apsFrame.sequence);
		return 0;
	} else {
		log_err("ezspSendUnicast node_id=0x%04X failure 0x%X",
		    node_id, status);
		return -1;
	}
}

/*
 * Send bind request to node
 */
int zb_send_bind_request(uint16_t node_id, uint8_t *src_eui,
			uint16_t cluster_id, uint8_t *dst_eui)
{
	EmberStatus status;

	status = emberBindRequest(node_id, src_eui, 1, cluster_id,
	    UNICAST_BINDING, dst_eui, 0, 1, EMBER_APS_OPTION_NONE);
	if (status != EMBER_SUCCESS) {
		log_err("emberBindRequest node_id=0x%04X cluster_id=0x%04X"
		    " returned %d", node_id, cluster_id, status);
		return -1;
	} else {
		log_debug("emberBindRequest node_id=0x%04X cluster_id=0x%04X"
			" success", node_id, cluster_id);
	}

	return 0;
}

/*
 * Send unbind request to node
 */
int zb_send_unbind_request(uint16_t node_id, uint8_t *src_eui,
			uint16_t cluster_id, uint8_t *dst_eui)
{
	EmberStatus status;

	status = emberUnbindRequest(node_id, src_eui, 1, cluster_id,
	    UNICAST_BINDING, dst_eui, 0, 1, EMBER_APS_OPTION_NONE);
	if (status != EMBER_SUCCESS) {
		log_err("emberUnbindRequest node_id=0x%04X cluster_id=0x%04X"
		    " returned %d", node_id, cluster_id, status);
		return -1;
	} else {
		log_debug("emberUnbindRequest node_id=0x%04X cluster_id=0x%04X"
			" success", node_id, cluster_id);
	}

	return 0;
}

/*
 * Send thermostat bind request to node
 */
int zb_thermostat_bind_request(uint16_t node_id, uint8_t *src_eui,
			uint16_t cluster_id)
{
	EmberStatus status;
	EmberEUI64 dst_eui;

	emberAfGetEui64(dst_eui);

	status = emberBindRequest(node_id, src_eui, 1, cluster_id,
	    UNICAST_BINDING, dst_eui, 0, 1, EMBER_APS_OPTION_NONE);
	if (status != EMBER_SUCCESS) {
		log_err("emberBindRequest node_id=0x%04X cluster_id=0x%04X"
		    " returned %d", node_id, cluster_id, status);
		return -1;
	} else {
		log_debug("emberBindRequest node_id=0x%04X cluster_id=0x%04X"
			" success", node_id, cluster_id);
	}

	return 0;
}

static void zb_print_network_info(void)
{
	unsigned char eui[8] = {0};
	char euiprt[8 * 3] = {0};

	emberAfGetEui64(eui);
	snprintf(euiprt, sizeof(euiprt),
	    "%02X:%02X:%02X:%02X:%02X:%02X:%02X:%02X",
	    eui[7], eui[6], eui[5], eui[4],
	    eui[3], eui[2], eui[1], eui[0]);
	log_debug("Net Addr=0x%02X, EUI64=%s, Net ID=0x%02X",
	    emberAfGetNodeId(), euiprt, emberAfGetPanId());
	return;
}

/*
 * Enable ZigBee radio and form network
 */
static int zb_network_enable(void)
{
	log_debug("begin network startup");

	/* Initialize the network co-processor (NCP) */
	emAfResetAndInitNCP();
	/* Main init callback */
	emberAfMainInitCallback();
	/* Initialize the ZCL Utilities */
	emberAfInit();

	log_debug("network startup complete");

	zb_print_network_info();

	return 0;
}

/*
 * Bring down the ZigBee network and disable the radio
 */
static int zb_network_disable(void)
{
	log_debug("shutdown stack");
	/* Reset the NCP and close the serial connection */
	/* TODO how do we force the NCP to reset ? */
	ezspClose();

	return 0;
}

/*
 * Initializes the zigbee platform
 */
static int zb_ember_stack_init(void)
{
	log_debug("begin stack init");

	/* Initialize the hal(hardware abstraction layer) */
	halInit();

	/* Safe to enable interrupts at this point */
	INTERRUPTS_ON();

	log_debug("begin serial parameters init");
	ashWriteConfig(baudRate, BAUD_RATE);
	ashWriteConfig(rtsCts, true);
	ashWriteConfig(stopBits, 1);
	ashWriteConfig(resetMethod, ASH_RESET_METHOD_RST);
	/* Set serial debug verbosity */
	if (log_debug_enabled()) {
		ashWriteConfig(traceFlags, TRACE_EVENTS | TRACE_EZSP);
	}

	/* Set serial port path */
	if (access(SERIAL_PATH, F_OK) < 0) {
		log_err("serial port %s unavailable: %m", SERIAL_PATH);
		return -1;
	}
	strncpy(ashHostConfig.serialPort, SERIAL_PATH, ASH_PORT_LEN-1);
	ashHostConfig.serialPort[ASH_PORT_LEN-1] = '\0';
	log_debug("serial parameters init complete");

	log_debug("Reset info: %d (%p)",
	    halGetResetInfo(), halGetResetString());

	/* This will initialize the stack of networks maintained by
	the framework, including setting the default network. */
	emAfInitializeNetworkIndexStack();

	/* We must initialize the endpoint information first so
	that they are correctly added by emAfResetAndInitNCP() */
	emberAfEndpointConfigure();

	zb_network_enable();

	log_debug("stack init complete");
	return 0;
}

/*
 * Handler called by the generic node management layer to prompt the network
 * interface layer to populate the nodes information and properties.
 * If callback is supplied and this function returns 0,
 * callback MUST be invoked when the operation completes.
 */
int zb_query_info_handler(struct node *node,
		void (*callback)(struct node *, enum node_network_result))
{
	ASSERT(node != NULL);
	log_info("%s: querying node info", node->addr);
	appd_set_query_complete_cb(node, callback);
	return 0;
}

/*
 * Handler called by the generic node management layer to prompt the network
 * interface layer to perform any setup operations required to manage the
 * node.
 * If callback is supplied and this function returns 0,
 * callback MUST be invoked when the operation completes.
 */
int zb_configure_handler(struct node *node,
		void (*callback)(struct node *, enum node_network_result))
{
	ASSERT(node != NULL);
	log_info("%s: configuring node", node->addr);
	appd_set_config_complete_cb(node, callback);
	return 0;
}

/*
 * Handler called by the generic node management layer to prompt the network
 * interface layer to send a new property value to the node.
 * If callback is supplied and this function returns 0,
 * callback MUST be invoked when the operation completes.
 */
int zb_prop_set_handler(struct node *node, struct node_prop *prop,
		void (*callback)(struct node *, struct node_prop *,
		enum node_network_result))
{
	uint16_t node_id;
	bool bool_value;
	int int_value;
	bool find = false;
	int ret = 0;

	ASSERT(node != NULL);
	ASSERT(prop != NULL);

	if (!(node->online)) {
		log_info("node %s is offline", node->addr);
		if (callback) {
			callback(node, prop, NETWORK_OFFLINE);
		}
		return 0;
	}

	node_id = appd_get_node_id(node);

	switch (prop->type) {
	case PROP_INTEGER:
		int_value = *(int *)(prop->val);
		log_debug("set node %s node_id 0x%04X int prop %s value %d",
		    node->addr, node_id, prop->name, int_value);
		if (!strcmp(prop->name, ZB_LEVEL_CTRL_PROP_NAME)) {
			find = true;
			ret = zb_send_level_control_request(node_id,
			    int_value);
		} else if (!strcmp(prop->name, ZB_SYSTEM_MODE)) {
			find = true;
			ret = zb_send_write_8bit_attr_request(node_id,
			    ZCL_THERMOSTAT_CLUSTER_ID,
			    ZCL_SYSTEM_MODE_ATTRIBUTE_ID,
			    ZCL_ENUM8_ATTRIBUTE_TYPE,
			    (uint8_t)(int_value & 0xFF));
		} else if (!strcmp(prop->name, ZB_COOLING_SETPOINT)) {
			find = true;
			ret = zb_send_write_16bit_attr_request(node_id,
			    ZCL_THERMOSTAT_CLUSTER_ID,
			    ZCL_OCCUPIED_COOLING_SETPOINT_ATTRIBUTE_ID,
			    ZCL_INT16S_ATTRIBUTE_TYPE,
			    ((uint16_t)(int_value & 0xFFFF) * 100));
		} else if (!strcmp(prop->name, ZB_HEATING_SETPOINT)) {
			find = true;
			ret = zb_send_write_16bit_attr_request(node_id,
			    ZCL_THERMOSTAT_CLUSTER_ID,
			    ZCL_OCCUPIED_HEATING_SETPOINT_ATTRIBUTE_ID,
			    ZCL_INT16S_ATTRIBUTE_TYPE,
			    ((uint16_t)(int_value & 0xFFFF) * 100));
		} else if (!strcmp(prop->name, ZB_FAN_MODE)) {
			find = true;
			ret = zb_send_write_8bit_attr_request(node_id,
			    ZCL_FAN_CONTROL_CLUSTER_ID,
			    ZCL_FAN_CONTROL_FAN_MODE_ATTRIBUTE_ID,
			    ZCL_ENUM8_ATTRIBUTE_TYPE,
			    (uint8_t)(int_value & 0xFF));
		}
		break;
	case PROP_STRING:
		log_debug("set node %s node_id 0x%04X string prop %s",
		    node->addr, node_id, prop->name);
		break;
	case PROP_BOOLEAN:
		bool_value = *(bool *)(prop->val);
		log_debug("set node %s node_id 0x%04X bool prop %s",
		    node->addr, node_id, prop->name);
		if (!strcmp(prop->name, ZB_ON_OFF_PROP_NAME)) {
			find = true;
			ret = zb_send_onoff_request(node_id, bool_value);
		}
		break;
	case PROP_DECIMAL:
		break;
	default:
		log_err("property type not supported: %s:%s:%s",
		    prop->subdevice->key, prop->template->key, prop->name);
		break;
	}

	if (find) {
		if (ret < 0) {
			if (callback) {
				callback(node, prop, NETWORK_UNKNOWN);
			}
		} else {
			appd_set_prop_complete_cb(node, callback);
		}
		return 0;
	} else {
		return -1;
	}
}


/*
 * Handler called by the generic node management layer to prompt the network
 * interface layer to remove the node from the network.
 * If callback is supplied and this function returns 0,
 * callback MUST be invoked when the operation completes.
 */
int zb_leave_handler(struct node *node,
		void (*callback)(struct node *, enum node_network_result))
{
	appd_set_leave_complete_cb(node, callback);
	return 0;
}

/*
 * Save ZigBee node info
 */
json_t *zb_conf_save_handler(const struct node *node)
{
	return appd_conf_save_handler(node);
}

/*
 * Restore ZigBee node info
 */
int zb_conf_loaded_handler(struct node *node, json_t *net_state_obj)
{
	return appd_conf_loaded_handler(node, net_state_obj);
}

/*
 * Gateway bind prop handler
 * cmd format: source node address,destination node address,cluster_id
 * format example: 00158D00006F95F1,00158D00006F9405,0x0006
*/
int zb_gw_bind_prop_handler(const char *cmd, char *result, int len)
{
	return appd_gw_bind_prop_handler(cmd, result, len);
}

/*
 * Initializes the zigbee platform
 */
int zb_init(void)
{
	/* Init appd interface */
	appd_interface_init();

	/* Initialize ember ZigBee protocol stack */
	if (zb_ember_stack_init()) {
		log_err("zb_ember_stack_init failed");
		return -1;
	}

	/* Disable nodes to join network */
	zb_permit_join(0, false);

	return 0;
}

/*
 * Start ZigBee protocol status update.
 */
int zb_start(void)
{
	/* Initialize protocol stack */
	if (zb_init() < 0) {
		log_err("ZigBee network stack initialization failed");
		return -1;
	}

	appd_update_all_node_state();
	return 0;
}

/*
 * Cleanup on exit
 */
void zb_exit(void)
{
	appd_interface_exit();
	zb_network_disable();
}

/*
 * Handle pending events
 */
void zb_poll(void)
{
	/* main loop */
	do {
		/* Periodically reset the watchdog. */
		halResetWatchdog();

		/* see if the NCP has anything waiting to send us */
		ezspTick();

		while (ezspCallbackPending()) {
			ezspCallback();
		}

		/* check if we have hit an EZSP Error and need to reset
		and init the NCP */
		if (ncpNeedsResetAndInit) {
			ncpNeedsResetAndInit = false;
			/* re-initialize the NCP */
			emAfResetAndInitNCP();
		}

		/* Wait until ECC operations are done.  Don't allow any of the
		clusters to send messages as the NCP is busy doing ECC */
		if (emAfIsCryptoOperationInProgress()) {
			return;
		}

		/* let the ZCL Utils run - this should go after ezspTick */
		emberAfTick();

		emberSerialBufferTick();

		emberAfRunEvents();

		/* After each interation through the main loop, our network
		index stack should be empty and we should be on
		the default network index again. */
		emAfAssertNetworkIndexStackIsEmpty();
	} while (!ashOkToSleep());
}

/*
 * Permit node join network
 */
int zb_permit_join(uint8_t duration, bool broadcast)
{
	EmberStatus status = emAfPermitJoin(duration, broadcast);
	if (status != EMBER_SUCCESS) {
		log_err("emAfPermitJoin returned %d", status);
		return -1;
	} else {
		log_debug("emAfPermitJoin success");
	}
	return 0;
}

