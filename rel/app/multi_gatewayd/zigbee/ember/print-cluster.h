// This file is generated by Simplicity Studio.  Please do not edit manually.
//
//

// This is the mapping of IDs to cluster names assuming a format according
// to the "EmberAfClusterName" defined in the ZCL header.
// The names of clusters that are not present, are removed.



#if defined(ZCL_USING_BASIC_CLUSTER_SERVER) || defined(ZCL_USING_BASIC_CLUSTER_CLIENT)
  #define __PRINTCLUSTER_BASIC_CLUSTER {ZCL_BASIC_CLUSTER_ID, "Basic" },
#else
  #define __PRINTCLUSTER_BASIC_CLUSTER
#endif
#if defined(ZCL_USING_POWER_CONFIG_CLUSTER_SERVER) || defined(ZCL_USING_POWER_CONFIG_CLUSTER_CLIENT)
  #define __PRINTCLUSTER_POWER_CONFIG_CLUSTER {ZCL_POWER_CONFIG_CLUSTER_ID, "Power Configuration" },
#else
  #define __PRINTCLUSTER_POWER_CONFIG_CLUSTER
#endif
#if defined(ZCL_USING_DEVICE_TEMP_CLUSTER_SERVER) || defined(ZCL_USING_DEVICE_TEMP_CLUSTER_CLIENT)
  #define __PRINTCLUSTER_DEVICE_TEMP_CLUSTER {ZCL_DEVICE_TEMP_CLUSTER_ID, "Device Temperature Configuration" },
#else
  #define __PRINTCLUSTER_DEVICE_TEMP_CLUSTER
#endif
#if defined(ZCL_USING_IDENTIFY_CLUSTER_SERVER) || defined(ZCL_USING_IDENTIFY_CLUSTER_CLIENT)
  #define __PRINTCLUSTER_IDENTIFY_CLUSTER {ZCL_IDENTIFY_CLUSTER_ID, "Identify" },
#else
  #define __PRINTCLUSTER_IDENTIFY_CLUSTER
#endif
#if defined(ZCL_USING_GROUPS_CLUSTER_SERVER) || defined(ZCL_USING_GROUPS_CLUSTER_CLIENT)
  #define __PRINTCLUSTER_GROUPS_CLUSTER {ZCL_GROUPS_CLUSTER_ID, "Groups" },
#else
  #define __PRINTCLUSTER_GROUPS_CLUSTER
#endif
#if defined(ZCL_USING_SCENES_CLUSTER_SERVER) || defined(ZCL_USING_SCENES_CLUSTER_CLIENT)
  #define __PRINTCLUSTER_SCENES_CLUSTER {ZCL_SCENES_CLUSTER_ID, "Scenes" },
#else
  #define __PRINTCLUSTER_SCENES_CLUSTER
#endif
#if defined(ZCL_USING_ON_OFF_CLUSTER_SERVER) || defined(ZCL_USING_ON_OFF_CLUSTER_CLIENT)
  #define __PRINTCLUSTER_ON_OFF_CLUSTER {ZCL_ON_OFF_CLUSTER_ID, "On/off" },
#else
  #define __PRINTCLUSTER_ON_OFF_CLUSTER
#endif
#if defined(ZCL_USING_ON_OFF_SWITCH_CONFIG_CLUSTER_SERVER) || defined(ZCL_USING_ON_OFF_SWITCH_CONFIG_CLUSTER_CLIENT)
  #define __PRINTCLUSTER_ON_OFF_SWITCH_CONFIG_CLUSTER {ZCL_ON_OFF_SWITCH_CONFIG_CLUSTER_ID, "On/off Switch Configuration" },
#else
  #define __PRINTCLUSTER_ON_OFF_SWITCH_CONFIG_CLUSTER
#endif
#if defined(ZCL_USING_LEVEL_CONTROL_CLUSTER_SERVER) || defined(ZCL_USING_LEVEL_CONTROL_CLUSTER_CLIENT)
  #define __PRINTCLUSTER_LEVEL_CONTROL_CLUSTER {ZCL_LEVEL_CONTROL_CLUSTER_ID, "Level Control" },
#else
  #define __PRINTCLUSTER_LEVEL_CONTROL_CLUSTER
#endif
#if defined(ZCL_USING_ALARM_CLUSTER_SERVER) || defined(ZCL_USING_ALARM_CLUSTER_CLIENT)
  #define __PRINTCLUSTER_ALARM_CLUSTER {ZCL_ALARM_CLUSTER_ID, "Alarms" },
#else
  #define __PRINTCLUSTER_ALARM_CLUSTER
#endif
#if defined(ZCL_USING_TIME_CLUSTER_SERVER) || defined(ZCL_USING_TIME_CLUSTER_CLIENT)
  #define __PRINTCLUSTER_TIME_CLUSTER {ZCL_TIME_CLUSTER_ID, "Time" },
#else
  #define __PRINTCLUSTER_TIME_CLUSTER
#endif
#if defined(ZCL_USING_RSSI_LOCATION_CLUSTER_SERVER) || defined(ZCL_USING_RSSI_LOCATION_CLUSTER_CLIENT)
  #define __PRINTCLUSTER_RSSI_LOCATION_CLUSTER {ZCL_RSSI_LOCATION_CLUSTER_ID, "RSSI Location" },
#else
  #define __PRINTCLUSTER_RSSI_LOCATION_CLUSTER
#endif
#if defined(ZCL_USING_BINARY_INPUT_BASIC_CLUSTER_SERVER) || defined(ZCL_USING_BINARY_INPUT_BASIC_CLUSTER_CLIENT)
  #define __PRINTCLUSTER_BINARY_INPUT_BASIC_CLUSTER {ZCL_BINARY_INPUT_BASIC_CLUSTER_ID, "Binary Input (Basic)" },
#else
  #define __PRINTCLUSTER_BINARY_INPUT_BASIC_CLUSTER
#endif
#if defined(ZCL_USING_COMMISSIONING_CLUSTER_SERVER) || defined(ZCL_USING_COMMISSIONING_CLUSTER_CLIENT)
  #define __PRINTCLUSTER_COMMISSIONING_CLUSTER {ZCL_COMMISSIONING_CLUSTER_ID, "Commissioning" },
#else
  #define __PRINTCLUSTER_COMMISSIONING_CLUSTER
#endif
#if defined(ZCL_USING_PARTITION_CLUSTER_SERVER) || defined(ZCL_USING_PARTITION_CLUSTER_CLIENT)
  #define __PRINTCLUSTER_PARTITION_CLUSTER {ZCL_PARTITION_CLUSTER_ID, "Partition" },
#else
  #define __PRINTCLUSTER_PARTITION_CLUSTER
#endif
#if defined(ZCL_USING_OTA_BOOTLOAD_CLUSTER_SERVER) || defined(ZCL_USING_OTA_BOOTLOAD_CLUSTER_CLIENT)
  #define __PRINTCLUSTER_OTA_BOOTLOAD_CLUSTER {ZCL_OTA_BOOTLOAD_CLUSTER_ID, "Over the Air Bootloading" },
#else
  #define __PRINTCLUSTER_OTA_BOOTLOAD_CLUSTER
#endif
#if defined(ZCL_USING_POWER_PROFILE_CLUSTER_SERVER) || defined(ZCL_USING_POWER_PROFILE_CLUSTER_CLIENT)
  #define __PRINTCLUSTER_POWER_PROFILE_CLUSTER {ZCL_POWER_PROFILE_CLUSTER_ID, "Power Profile" },
#else
  #define __PRINTCLUSTER_POWER_PROFILE_CLUSTER
#endif
#if defined(ZCL_USING_APPLIANCE_CONTROL_CLUSTER_SERVER) || defined(ZCL_USING_APPLIANCE_CONTROL_CLUSTER_CLIENT)
  #define __PRINTCLUSTER_APPLIANCE_CONTROL_CLUSTER {ZCL_APPLIANCE_CONTROL_CLUSTER_ID, "Appliance Control" },
#else
  #define __PRINTCLUSTER_APPLIANCE_CONTROL_CLUSTER
#endif
#if defined(ZCL_USING_POLL_CONTROL_CLUSTER_SERVER) || defined(ZCL_USING_POLL_CONTROL_CLUSTER_CLIENT)
  #define __PRINTCLUSTER_POLL_CONTROL_CLUSTER {ZCL_POLL_CONTROL_CLUSTER_ID, "Poll Control" },
#else
  #define __PRINTCLUSTER_POLL_CONTROL_CLUSTER
#endif
#if defined(ZCL_USING_GREEN_POWER_CLUSTER_SERVER) || defined(ZCL_USING_GREEN_POWER_CLUSTER_CLIENT)
  #define __PRINTCLUSTER_GREEN_POWER_CLUSTER {ZCL_GREEN_POWER_CLUSTER_ID, "Green Power" },
#else
  #define __PRINTCLUSTER_GREEN_POWER_CLUSTER
#endif
#if defined(ZCL_USING_KEEPALIVE_CLUSTER_SERVER) || defined(ZCL_USING_KEEPALIVE_CLUSTER_CLIENT)
  #define __PRINTCLUSTER_KEEPALIVE_CLUSTER {ZCL_KEEPALIVE_CLUSTER_ID, "Keep-Alive" },
#else
  #define __PRINTCLUSTER_KEEPALIVE_CLUSTER
#endif
#if defined(ZCL_USING_SHADE_CONFIG_CLUSTER_SERVER) || defined(ZCL_USING_SHADE_CONFIG_CLUSTER_CLIENT)
  #define __PRINTCLUSTER_SHADE_CONFIG_CLUSTER {ZCL_SHADE_CONFIG_CLUSTER_ID, "Shade Configuration" },
#else
  #define __PRINTCLUSTER_SHADE_CONFIG_CLUSTER
#endif
#if defined(ZCL_USING_DOOR_LOCK_CLUSTER_SERVER) || defined(ZCL_USING_DOOR_LOCK_CLUSTER_CLIENT)
  #define __PRINTCLUSTER_DOOR_LOCK_CLUSTER {ZCL_DOOR_LOCK_CLUSTER_ID, "Door Lock" },
#else
  #define __PRINTCLUSTER_DOOR_LOCK_CLUSTER
#endif
#if defined(ZCL_USING_WINDOW_COVERING_CLUSTER_SERVER) || defined(ZCL_USING_WINDOW_COVERING_CLUSTER_CLIENT)
  #define __PRINTCLUSTER_WINDOW_COVERING_CLUSTER {ZCL_WINDOW_COVERING_CLUSTER_ID, "Window Covering" },
#else
  #define __PRINTCLUSTER_WINDOW_COVERING_CLUSTER
#endif
#if defined(ZCL_USING_PUMP_CONFIG_CONTROL_CLUSTER_SERVER) || defined(ZCL_USING_PUMP_CONFIG_CONTROL_CLUSTER_CLIENT)
  #define __PRINTCLUSTER_PUMP_CONFIG_CONTROL_CLUSTER {ZCL_PUMP_CONFIG_CONTROL_CLUSTER_ID, "Pump Configuration and Control" },
#else
  #define __PRINTCLUSTER_PUMP_CONFIG_CONTROL_CLUSTER
#endif
#if defined(ZCL_USING_THERMOSTAT_CLUSTER_SERVER) || defined(ZCL_USING_THERMOSTAT_CLUSTER_CLIENT)
  #define __PRINTCLUSTER_THERMOSTAT_CLUSTER {ZCL_THERMOSTAT_CLUSTER_ID, "Thermostat" },
#else
  #define __PRINTCLUSTER_THERMOSTAT_CLUSTER
#endif
#if defined(ZCL_USING_FAN_CONTROL_CLUSTER_SERVER) || defined(ZCL_USING_FAN_CONTROL_CLUSTER_CLIENT)
  #define __PRINTCLUSTER_FAN_CONTROL_CLUSTER {ZCL_FAN_CONTROL_CLUSTER_ID, "Fan Control" },
#else
  #define __PRINTCLUSTER_FAN_CONTROL_CLUSTER
#endif
#if defined(ZCL_USING_DEHUMID_CONTROL_CLUSTER_SERVER) || defined(ZCL_USING_DEHUMID_CONTROL_CLUSTER_CLIENT)
  #define __PRINTCLUSTER_DEHUMID_CONTROL_CLUSTER {ZCL_DEHUMID_CONTROL_CLUSTER_ID, "Dehumidification Control" },
#else
  #define __PRINTCLUSTER_DEHUMID_CONTROL_CLUSTER
#endif
#if defined(ZCL_USING_THERMOSTAT_UI_CONFIG_CLUSTER_SERVER) || defined(ZCL_USING_THERMOSTAT_UI_CONFIG_CLUSTER_CLIENT)
  #define __PRINTCLUSTER_THERMOSTAT_UI_CONFIG_CLUSTER {ZCL_THERMOSTAT_UI_CONFIG_CLUSTER_ID, "Thermostat User Interface Configuration" },
#else
  #define __PRINTCLUSTER_THERMOSTAT_UI_CONFIG_CLUSTER
#endif
#if defined(ZCL_USING_COLOR_CONTROL_CLUSTER_SERVER) || defined(ZCL_USING_COLOR_CONTROL_CLUSTER_CLIENT)
  #define __PRINTCLUSTER_COLOR_CONTROL_CLUSTER {ZCL_COLOR_CONTROL_CLUSTER_ID, "Color Control" },
#else
  #define __PRINTCLUSTER_COLOR_CONTROL_CLUSTER
#endif
#if defined(ZCL_USING_BALLAST_CONFIGURATION_CLUSTER_SERVER) || defined(ZCL_USING_BALLAST_CONFIGURATION_CLUSTER_CLIENT)
  #define __PRINTCLUSTER_BALLAST_CONFIGURATION_CLUSTER {ZCL_BALLAST_CONFIGURATION_CLUSTER_ID, "Ballast Configuration" },
#else
  #define __PRINTCLUSTER_BALLAST_CONFIGURATION_CLUSTER
#endif
#if defined(ZCL_USING_ILLUM_MEASUREMENT_CLUSTER_SERVER) || defined(ZCL_USING_ILLUM_MEASUREMENT_CLUSTER_CLIENT)
  #define __PRINTCLUSTER_ILLUM_MEASUREMENT_CLUSTER {ZCL_ILLUM_MEASUREMENT_CLUSTER_ID, "Illuminance Measurement" },
#else
  #define __PRINTCLUSTER_ILLUM_MEASUREMENT_CLUSTER
#endif
#if defined(ZCL_USING_ILLUM_LEVEL_SENSING_CLUSTER_SERVER) || defined(ZCL_USING_ILLUM_LEVEL_SENSING_CLUSTER_CLIENT)
  #define __PRINTCLUSTER_ILLUM_LEVEL_SENSING_CLUSTER {ZCL_ILLUM_LEVEL_SENSING_CLUSTER_ID, "Illuminance Level Sensing" },
#else
  #define __PRINTCLUSTER_ILLUM_LEVEL_SENSING_CLUSTER
#endif
#if defined(ZCL_USING_TEMP_MEASUREMENT_CLUSTER_SERVER) || defined(ZCL_USING_TEMP_MEASUREMENT_CLUSTER_CLIENT)
  #define __PRINTCLUSTER_TEMP_MEASUREMENT_CLUSTER {ZCL_TEMP_MEASUREMENT_CLUSTER_ID, "Temperature Measurement" },
#else
  #define __PRINTCLUSTER_TEMP_MEASUREMENT_CLUSTER
#endif
#if defined(ZCL_USING_PRESSURE_MEASUREMENT_CLUSTER_SERVER) || defined(ZCL_USING_PRESSURE_MEASUREMENT_CLUSTER_CLIENT)
  #define __PRINTCLUSTER_PRESSURE_MEASUREMENT_CLUSTER {ZCL_PRESSURE_MEASUREMENT_CLUSTER_ID, "Pressure Measurement" },
#else
  #define __PRINTCLUSTER_PRESSURE_MEASUREMENT_CLUSTER
#endif
#if defined(ZCL_USING_FLOW_MEASUREMENT_CLUSTER_SERVER) || defined(ZCL_USING_FLOW_MEASUREMENT_CLUSTER_CLIENT)
  #define __PRINTCLUSTER_FLOW_MEASUREMENT_CLUSTER {ZCL_FLOW_MEASUREMENT_CLUSTER_ID, "Flow Measurement" },
#else
  #define __PRINTCLUSTER_FLOW_MEASUREMENT_CLUSTER
#endif
#if defined(ZCL_USING_RELATIVE_HUMIDITY_MEASUREMENT_CLUSTER_SERVER) || defined(ZCL_USING_RELATIVE_HUMIDITY_MEASUREMENT_CLUSTER_CLIENT)
  #define __PRINTCLUSTER_RELATIVE_HUMIDITY_MEASUREMENT_CLUSTER {ZCL_RELATIVE_HUMIDITY_MEASUREMENT_CLUSTER_ID, "Relative Humidity Measurement" },
#else
  #define __PRINTCLUSTER_RELATIVE_HUMIDITY_MEASUREMENT_CLUSTER
#endif
#if defined(ZCL_USING_OCCUPANCY_SENSING_CLUSTER_SERVER) || defined(ZCL_USING_OCCUPANCY_SENSING_CLUSTER_CLIENT)
  #define __PRINTCLUSTER_OCCUPANCY_SENSING_CLUSTER {ZCL_OCCUPANCY_SENSING_CLUSTER_ID, "Occupancy Sensing" },
#else
  #define __PRINTCLUSTER_OCCUPANCY_SENSING_CLUSTER
#endif
#if defined(ZCL_USING_IAS_ZONE_CLUSTER_SERVER) || defined(ZCL_USING_IAS_ZONE_CLUSTER_CLIENT)
  #define __PRINTCLUSTER_IAS_ZONE_CLUSTER {ZCL_IAS_ZONE_CLUSTER_ID, "IAS Zone" },
#else
  #define __PRINTCLUSTER_IAS_ZONE_CLUSTER
#endif
#if defined(ZCL_USING_IAS_ACE_CLUSTER_SERVER) || defined(ZCL_USING_IAS_ACE_CLUSTER_CLIENT)
  #define __PRINTCLUSTER_IAS_ACE_CLUSTER {ZCL_IAS_ACE_CLUSTER_ID, "IAS ACE" },
#else
  #define __PRINTCLUSTER_IAS_ACE_CLUSTER
#endif
#if defined(ZCL_USING_IAS_WD_CLUSTER_SERVER) || defined(ZCL_USING_IAS_WD_CLUSTER_CLIENT)
  #define __PRINTCLUSTER_IAS_WD_CLUSTER {ZCL_IAS_WD_CLUSTER_ID, "IAS WD" },
#else
  #define __PRINTCLUSTER_IAS_WD_CLUSTER
#endif
#if defined(ZCL_USING_GENERIC_TUNNEL_CLUSTER_SERVER) || defined(ZCL_USING_GENERIC_TUNNEL_CLUSTER_CLIENT)
  #define __PRINTCLUSTER_GENERIC_TUNNEL_CLUSTER {ZCL_GENERIC_TUNNEL_CLUSTER_ID, "Generic Tunnel" },
#else
  #define __PRINTCLUSTER_GENERIC_TUNNEL_CLUSTER
#endif
#if defined(ZCL_USING_BACNET_PROTOCOL_TUNNEL_CLUSTER_SERVER) || defined(ZCL_USING_BACNET_PROTOCOL_TUNNEL_CLUSTER_CLIENT)
  #define __PRINTCLUSTER_BACNET_PROTOCOL_TUNNEL_CLUSTER {ZCL_BACNET_PROTOCOL_TUNNEL_CLUSTER_ID, "BACnet Protocol Tunnel" },
#else
  #define __PRINTCLUSTER_BACNET_PROTOCOL_TUNNEL_CLUSTER
#endif
#if defined(ZCL_USING_11073_PROTOCOL_TUNNEL_CLUSTER_SERVER) || defined(ZCL_USING_11073_PROTOCOL_TUNNEL_CLUSTER_CLIENT)
  #define __PRINTCLUSTER_11073_PROTOCOL_TUNNEL_CLUSTER {ZCL_11073_PROTOCOL_TUNNEL_CLUSTER_ID, "11073 Protocol Tunnel" },
#else
  #define __PRINTCLUSTER_11073_PROTOCOL_TUNNEL_CLUSTER
#endif
#if defined(ZCL_USING_ISO7816_PROTOCOL_TUNNEL_CLUSTER_SERVER) || defined(ZCL_USING_ISO7816_PROTOCOL_TUNNEL_CLUSTER_CLIENT)
  #define __PRINTCLUSTER_ISO7816_PROTOCOL_TUNNEL_CLUSTER {ZCL_ISO7816_PROTOCOL_TUNNEL_CLUSTER_ID, "ISO 7816 Protocol Tunnel" },
#else
  #define __PRINTCLUSTER_ISO7816_PROTOCOL_TUNNEL_CLUSTER
#endif
#if defined(ZCL_USING_PRICE_CLUSTER_SERVER) || defined(ZCL_USING_PRICE_CLUSTER_CLIENT)
  #define __PRINTCLUSTER_PRICE_CLUSTER {ZCL_PRICE_CLUSTER_ID, "Price" },
#else
  #define __PRINTCLUSTER_PRICE_CLUSTER
#endif
#if defined(ZCL_USING_DEMAND_RESPONSE_LOAD_CONTROL_CLUSTER_SERVER) || defined(ZCL_USING_DEMAND_RESPONSE_LOAD_CONTROL_CLUSTER_CLIENT)
  #define __PRINTCLUSTER_DEMAND_RESPONSE_LOAD_CONTROL_CLUSTER {ZCL_DEMAND_RESPONSE_LOAD_CONTROL_CLUSTER_ID, "Demand Response and Load Control" },
#else
  #define __PRINTCLUSTER_DEMAND_RESPONSE_LOAD_CONTROL_CLUSTER
#endif
#if defined(ZCL_USING_SIMPLE_METERING_CLUSTER_SERVER) || defined(ZCL_USING_SIMPLE_METERING_CLUSTER_CLIENT)
  #define __PRINTCLUSTER_SIMPLE_METERING_CLUSTER {ZCL_SIMPLE_METERING_CLUSTER_ID, "Simple Metering" },
#else
  #define __PRINTCLUSTER_SIMPLE_METERING_CLUSTER
#endif
#if defined(ZCL_USING_MESSAGING_CLUSTER_SERVER) || defined(ZCL_USING_MESSAGING_CLUSTER_CLIENT)
  #define __PRINTCLUSTER_MESSAGING_CLUSTER {ZCL_MESSAGING_CLUSTER_ID, "Messaging" },
#else
  #define __PRINTCLUSTER_MESSAGING_CLUSTER
#endif
#if defined(ZCL_USING_TUNNELING_CLUSTER_SERVER) || defined(ZCL_USING_TUNNELING_CLUSTER_CLIENT)
  #define __PRINTCLUSTER_TUNNELING_CLUSTER {ZCL_TUNNELING_CLUSTER_ID, "Tunneling" },
#else
  #define __PRINTCLUSTER_TUNNELING_CLUSTER
#endif
#if defined(ZCL_USING_PREPAYMENT_CLUSTER_SERVER) || defined(ZCL_USING_PREPAYMENT_CLUSTER_CLIENT)
  #define __PRINTCLUSTER_PREPAYMENT_CLUSTER {ZCL_PREPAYMENT_CLUSTER_ID, "Prepayment" },
#else
  #define __PRINTCLUSTER_PREPAYMENT_CLUSTER
#endif
#if defined(ZCL_USING_ENERGY_MANAGEMENT_CLUSTER_SERVER) || defined(ZCL_USING_ENERGY_MANAGEMENT_CLUSTER_CLIENT)
  #define __PRINTCLUSTER_ENERGY_MANAGEMENT_CLUSTER {ZCL_ENERGY_MANAGEMENT_CLUSTER_ID, "Energy Management" },
#else
  #define __PRINTCLUSTER_ENERGY_MANAGEMENT_CLUSTER
#endif
#if defined(ZCL_USING_CALENDAR_CLUSTER_SERVER) || defined(ZCL_USING_CALENDAR_CLUSTER_CLIENT)
  #define __PRINTCLUSTER_CALENDAR_CLUSTER {ZCL_CALENDAR_CLUSTER_ID, "Calendar" },
#else
  #define __PRINTCLUSTER_CALENDAR_CLUSTER
#endif
#if defined(ZCL_USING_DEVICE_MANAGEMENT_CLUSTER_SERVER) || defined(ZCL_USING_DEVICE_MANAGEMENT_CLUSTER_CLIENT)
  #define __PRINTCLUSTER_DEVICE_MANAGEMENT_CLUSTER {ZCL_DEVICE_MANAGEMENT_CLUSTER_ID, "Device Management" },
#else
  #define __PRINTCLUSTER_DEVICE_MANAGEMENT_CLUSTER
#endif
#if defined(ZCL_USING_EVENTS_CLUSTER_SERVER) || defined(ZCL_USING_EVENTS_CLUSTER_CLIENT)
  #define __PRINTCLUSTER_EVENTS_CLUSTER {ZCL_EVENTS_CLUSTER_ID, "Events" },
#else
  #define __PRINTCLUSTER_EVENTS_CLUSTER
#endif
#if defined(ZCL_USING_MDU_PAIRING_CLUSTER_SERVER) || defined(ZCL_USING_MDU_PAIRING_CLUSTER_CLIENT)
  #define __PRINTCLUSTER_MDU_PAIRING_CLUSTER {ZCL_MDU_PAIRING_CLUSTER_ID, "MDU Pairing" },
#else
  #define __PRINTCLUSTER_MDU_PAIRING_CLUSTER
#endif
#if defined(ZCL_USING_KEY_ESTABLISHMENT_CLUSTER_SERVER) || defined(ZCL_USING_KEY_ESTABLISHMENT_CLUSTER_CLIENT)
  #define __PRINTCLUSTER_KEY_ESTABLISHMENT_CLUSTER {ZCL_KEY_ESTABLISHMENT_CLUSTER_ID, "Key Establishment" },
#else
  #define __PRINTCLUSTER_KEY_ESTABLISHMENT_CLUSTER
#endif
#if defined(ZCL_USING_INFORMATION_CLUSTER_SERVER) || defined(ZCL_USING_INFORMATION_CLUSTER_CLIENT)
  #define __PRINTCLUSTER_INFORMATION_CLUSTER {ZCL_INFORMATION_CLUSTER_ID, "Information" },
#else
  #define __PRINTCLUSTER_INFORMATION_CLUSTER
#endif
#if defined(ZCL_USING_DATA_SHARING_CLUSTER_SERVER) || defined(ZCL_USING_DATA_SHARING_CLUSTER_CLIENT)
  #define __PRINTCLUSTER_DATA_SHARING_CLUSTER {ZCL_DATA_SHARING_CLUSTER_ID, "Data Sharing" },
#else
  #define __PRINTCLUSTER_DATA_SHARING_CLUSTER
#endif
#if defined(ZCL_USING_GAMING_CLUSTER_SERVER) || defined(ZCL_USING_GAMING_CLUSTER_CLIENT)
  #define __PRINTCLUSTER_GAMING_CLUSTER {ZCL_GAMING_CLUSTER_ID, "Gaming" },
#else
  #define __PRINTCLUSTER_GAMING_CLUSTER
#endif
#if defined(ZCL_USING_DATA_RATE_CONTROL_CLUSTER_SERVER) || defined(ZCL_USING_DATA_RATE_CONTROL_CLUSTER_CLIENT)
  #define __PRINTCLUSTER_DATA_RATE_CONTROL_CLUSTER {ZCL_DATA_RATE_CONTROL_CLUSTER_ID, "Data Rate Control" },
#else
  #define __PRINTCLUSTER_DATA_RATE_CONTROL_CLUSTER
#endif
#if defined(ZCL_USING_VOICE_OVER_ZIGBEE_CLUSTER_SERVER) || defined(ZCL_USING_VOICE_OVER_ZIGBEE_CLUSTER_CLIENT)
  #define __PRINTCLUSTER_VOICE_OVER_ZIGBEE_CLUSTER {ZCL_VOICE_OVER_ZIGBEE_CLUSTER_ID, "Voice over ZigBee" },
#else
  #define __PRINTCLUSTER_VOICE_OVER_ZIGBEE_CLUSTER
#endif
#if defined(ZCL_USING_CHATTING_CLUSTER_SERVER) || defined(ZCL_USING_CHATTING_CLUSTER_CLIENT)
  #define __PRINTCLUSTER_CHATTING_CLUSTER {ZCL_CHATTING_CLUSTER_ID, "Chatting" },
#else
  #define __PRINTCLUSTER_CHATTING_CLUSTER
#endif
#if defined(ZCL_USING_PAYMENT_CLUSTER_SERVER) || defined(ZCL_USING_PAYMENT_CLUSTER_CLIENT)
  #define __PRINTCLUSTER_PAYMENT_CLUSTER {ZCL_PAYMENT_CLUSTER_ID, "Payment" },
#else
  #define __PRINTCLUSTER_PAYMENT_CLUSTER
#endif
#if defined(ZCL_USING_BILLING_CLUSTER_SERVER) || defined(ZCL_USING_BILLING_CLUSTER_CLIENT)
  #define __PRINTCLUSTER_BILLING_CLUSTER {ZCL_BILLING_CLUSTER_ID, "Billing" },
#else
  #define __PRINTCLUSTER_BILLING_CLUSTER
#endif
#if defined(ZCL_USING_APPLIANCE_IDENTIFICATION_CLUSTER_SERVER) || defined(ZCL_USING_APPLIANCE_IDENTIFICATION_CLUSTER_CLIENT)
  #define __PRINTCLUSTER_APPLIANCE_IDENTIFICATION_CLUSTER {ZCL_APPLIANCE_IDENTIFICATION_CLUSTER_ID, "Appliance Identification" },
#else
  #define __PRINTCLUSTER_APPLIANCE_IDENTIFICATION_CLUSTER
#endif
#if defined(ZCL_USING_METER_IDENTIFICATION_CLUSTER_SERVER) || defined(ZCL_USING_METER_IDENTIFICATION_CLUSTER_CLIENT)
  #define __PRINTCLUSTER_METER_IDENTIFICATION_CLUSTER {ZCL_METER_IDENTIFICATION_CLUSTER_ID, "Meter Identification" },
#else
  #define __PRINTCLUSTER_METER_IDENTIFICATION_CLUSTER
#endif
#if defined(ZCL_USING_APPLIANCE_EVENTS_AND_ALERT_CLUSTER_SERVER) || defined(ZCL_USING_APPLIANCE_EVENTS_AND_ALERT_CLUSTER_CLIENT)
  #define __PRINTCLUSTER_APPLIANCE_EVENTS_AND_ALERT_CLUSTER {ZCL_APPLIANCE_EVENTS_AND_ALERT_CLUSTER_ID, "Appliance Events and Alert" },
#else
  #define __PRINTCLUSTER_APPLIANCE_EVENTS_AND_ALERT_CLUSTER
#endif
#if defined(ZCL_USING_APPLIANCE_STATISTICS_CLUSTER_SERVER) || defined(ZCL_USING_APPLIANCE_STATISTICS_CLUSTER_CLIENT)
  #define __PRINTCLUSTER_APPLIANCE_STATISTICS_CLUSTER {ZCL_APPLIANCE_STATISTICS_CLUSTER_ID, "Appliance Statistics" },
#else
  #define __PRINTCLUSTER_APPLIANCE_STATISTICS_CLUSTER
#endif
#if defined(ZCL_USING_ELECTRICAL_MEASUREMENT_CLUSTER_SERVER) || defined(ZCL_USING_ELECTRICAL_MEASUREMENT_CLUSTER_CLIENT)
  #define __PRINTCLUSTER_ELECTRICAL_MEASUREMENT_CLUSTER {ZCL_ELECTRICAL_MEASUREMENT_CLUSTER_ID, "Electrical Measurement" },
#else
  #define __PRINTCLUSTER_ELECTRICAL_MEASUREMENT_CLUSTER
#endif
#if defined(ZCL_USING_DIAGNOSTICS_CLUSTER_SERVER) || defined(ZCL_USING_DIAGNOSTICS_CLUSTER_CLIENT)
  #define __PRINTCLUSTER_DIAGNOSTICS_CLUSTER {ZCL_DIAGNOSTICS_CLUSTER_ID, "Diagnostics" },
#else
  #define __PRINTCLUSTER_DIAGNOSTICS_CLUSTER
#endif
#if defined(ZCL_USING_ZLL_COMMISSIONING_CLUSTER_SERVER) || defined(ZCL_USING_ZLL_COMMISSIONING_CLUSTER_CLIENT)
  #define __PRINTCLUSTER_ZLL_COMMISSIONING_CLUSTER {ZCL_ZLL_COMMISSIONING_CLUSTER_ID, "ZLL Commissioning" },
#else
  #define __PRINTCLUSTER_ZLL_COMMISSIONING_CLUSTER
#endif
#if defined(ZCL_USING_SAMPLE_MFG_SPECIFIC_CLUSTER_SERVER) || defined(ZCL_USING_SAMPLE_MFG_SPECIFIC_CLUSTER_CLIENT)
  #define __PRINTCLUSTER_SAMPLE_MFG_SPECIFIC_CLUSTER {ZCL_SAMPLE_MFG_SPECIFIC_CLUSTER_ID, "Sample Mfg Specific Cluster" },
#else
  #define __PRINTCLUSTER_SAMPLE_MFG_SPECIFIC_CLUSTER
#endif
#if defined(ZCL_USING_OTA_CONFIGURATION_CLUSTER_SERVER) || defined(ZCL_USING_OTA_CONFIGURATION_CLUSTER_CLIENT)
  #define __PRINTCLUSTER_OTA_CONFIGURATION_CLUSTER {ZCL_OTA_CONFIGURATION_CLUSTER_ID, "Configuration Cluster" },
#else
  #define __PRINTCLUSTER_OTA_CONFIGURATION_CLUSTER
#endif
#if defined(ZCL_USING_MFGLIB_CLUSTER_SERVER) || defined(ZCL_USING_MFGLIB_CLUSTER_CLIENT)
  #define __PRINTCLUSTER_MFGLIB_CLUSTER {ZCL_MFGLIB_CLUSTER_ID, "MFGLIB Cluster" },
#else
  #define __PRINTCLUSTER_MFGLIB_CLUSTER
#endif
#define CLUSTER_IDS_TO_NAMES \
  __PRINTCLUSTER_BASIC_CLUSTER \
  __PRINTCLUSTER_POWER_CONFIG_CLUSTER \
  __PRINTCLUSTER_DEVICE_TEMP_CLUSTER \
  __PRINTCLUSTER_IDENTIFY_CLUSTER \
  __PRINTCLUSTER_GROUPS_CLUSTER \
  __PRINTCLUSTER_SCENES_CLUSTER \
  __PRINTCLUSTER_ON_OFF_CLUSTER \
  __PRINTCLUSTER_ON_OFF_SWITCH_CONFIG_CLUSTER \
  __PRINTCLUSTER_LEVEL_CONTROL_CLUSTER \
  __PRINTCLUSTER_ALARM_CLUSTER \
  __PRINTCLUSTER_TIME_CLUSTER \
  __PRINTCLUSTER_RSSI_LOCATION_CLUSTER \
  __PRINTCLUSTER_BINARY_INPUT_BASIC_CLUSTER \
  __PRINTCLUSTER_COMMISSIONING_CLUSTER \
  __PRINTCLUSTER_PARTITION_CLUSTER \
  __PRINTCLUSTER_OTA_BOOTLOAD_CLUSTER \
  __PRINTCLUSTER_POWER_PROFILE_CLUSTER \
  __PRINTCLUSTER_APPLIANCE_CONTROL_CLUSTER \
  __PRINTCLUSTER_POLL_CONTROL_CLUSTER \
  __PRINTCLUSTER_GREEN_POWER_CLUSTER \
  __PRINTCLUSTER_KEEPALIVE_CLUSTER \
  __PRINTCLUSTER_SHADE_CONFIG_CLUSTER \
  __PRINTCLUSTER_DOOR_LOCK_CLUSTER \
  __PRINTCLUSTER_WINDOW_COVERING_CLUSTER \
  __PRINTCLUSTER_PUMP_CONFIG_CONTROL_CLUSTER \
  __PRINTCLUSTER_THERMOSTAT_CLUSTER \
  __PRINTCLUSTER_FAN_CONTROL_CLUSTER \
  __PRINTCLUSTER_DEHUMID_CONTROL_CLUSTER \
  __PRINTCLUSTER_THERMOSTAT_UI_CONFIG_CLUSTER \
  __PRINTCLUSTER_COLOR_CONTROL_CLUSTER \
  __PRINTCLUSTER_BALLAST_CONFIGURATION_CLUSTER \
  __PRINTCLUSTER_ILLUM_MEASUREMENT_CLUSTER \
  __PRINTCLUSTER_ILLUM_LEVEL_SENSING_CLUSTER \
  __PRINTCLUSTER_TEMP_MEASUREMENT_CLUSTER \
  __PRINTCLUSTER_PRESSURE_MEASUREMENT_CLUSTER \
  __PRINTCLUSTER_FLOW_MEASUREMENT_CLUSTER \
  __PRINTCLUSTER_RELATIVE_HUMIDITY_MEASUREMENT_CLUSTER \
  __PRINTCLUSTER_OCCUPANCY_SENSING_CLUSTER \
  __PRINTCLUSTER_IAS_ZONE_CLUSTER \
  __PRINTCLUSTER_IAS_ACE_CLUSTER \
  __PRINTCLUSTER_IAS_WD_CLUSTER \
  __PRINTCLUSTER_GENERIC_TUNNEL_CLUSTER \
  __PRINTCLUSTER_BACNET_PROTOCOL_TUNNEL_CLUSTER \
  __PRINTCLUSTER_11073_PROTOCOL_TUNNEL_CLUSTER \
  __PRINTCLUSTER_ISO7816_PROTOCOL_TUNNEL_CLUSTER \
  __PRINTCLUSTER_PRICE_CLUSTER \
  __PRINTCLUSTER_DEMAND_RESPONSE_LOAD_CONTROL_CLUSTER \
  __PRINTCLUSTER_SIMPLE_METERING_CLUSTER \
  __PRINTCLUSTER_MESSAGING_CLUSTER \
  __PRINTCLUSTER_TUNNELING_CLUSTER \
  __PRINTCLUSTER_PREPAYMENT_CLUSTER \
  __PRINTCLUSTER_ENERGY_MANAGEMENT_CLUSTER \
  __PRINTCLUSTER_CALENDAR_CLUSTER \
  __PRINTCLUSTER_DEVICE_MANAGEMENT_CLUSTER \
  __PRINTCLUSTER_EVENTS_CLUSTER \
  __PRINTCLUSTER_MDU_PAIRING_CLUSTER \
  __PRINTCLUSTER_KEY_ESTABLISHMENT_CLUSTER \
  __PRINTCLUSTER_INFORMATION_CLUSTER \
  __PRINTCLUSTER_DATA_SHARING_CLUSTER \
  __PRINTCLUSTER_GAMING_CLUSTER \
  __PRINTCLUSTER_DATA_RATE_CONTROL_CLUSTER \
  __PRINTCLUSTER_VOICE_OVER_ZIGBEE_CLUSTER \
  __PRINTCLUSTER_CHATTING_CLUSTER \
  __PRINTCLUSTER_PAYMENT_CLUSTER \
  __PRINTCLUSTER_BILLING_CLUSTER \
  __PRINTCLUSTER_APPLIANCE_IDENTIFICATION_CLUSTER \
  __PRINTCLUSTER_METER_IDENTIFICATION_CLUSTER \
  __PRINTCLUSTER_APPLIANCE_EVENTS_AND_ALERT_CLUSTER \
  __PRINTCLUSTER_APPLIANCE_STATISTICS_CLUSTER \
  __PRINTCLUSTER_ELECTRICAL_MEASUREMENT_CLUSTER \
  __PRINTCLUSTER_DIAGNOSTICS_CLUSTER \
  __PRINTCLUSTER_ZLL_COMMISSIONING_CLUSTER \
  __PRINTCLUSTER_SAMPLE_MFG_SPECIFIC_CLUSTER \
  __PRINTCLUSTER_OTA_CONFIGURATION_CLUSTER \
  __PRINTCLUSTER_MFGLIB_CLUSTER \


#define MAX_CLUSTER_NAME_LENGTH  39
