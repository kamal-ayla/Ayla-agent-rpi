#! /usr/bin/tclsh
#
# Copyright 2011-2018 Ayla Networks, Inc.  All rights reserved.
#
# Use of the accompanying software is permitted only in accordance
# with and subject to the terms of the Software License Agreement
# with Ayla Networks, Inc., a copy of which can be obtained from
# Ayla Networks, Inc.
#

package require xml
package require json::write

set log_file "log.txt"

#
# AFS config
# If the serial number directory is present, we run offline
#
set afs_data afs_data.txt
set afs_dir "mfg_data/sn*"
set afs_used_dir "mfg_data/used_sns"
set afs_err afs_err.txt
set afs_header afs_header.txt
set afs_temp ""
set afs_file ""
if {[llength [glob -type d -nocomplain $afs_dir]]} {
	set afs_offline 1
} else {
	set afs_offline 0
	set afs https://afs.aylanetworks.com/apiv1
	set afs_key "$env(AFS_FILE)"
}
set curl "curl"

set err(serial)		60
set err(serial_old)	61
set err(serial_old_time) 62
set err(serial_old_conf) 63
set err(serial_get)	64
set err(serial_none)	65
set err(serial_write)	66
set err(serial_parse)	67
set err(serial_not_mfg) 68
set err(serial_not_passed) 69
set err(serial_test_time) 70
set err(serial_no_mac)	71

set assign(dsn) ""
set assign(serial) ""
set assign(mac_addr) ""
set assign(model) "AY001MRT1"
set assign(mfg_serial) "0"
set assign(mfg_model) "linux"
set assign(stm32_sig) "linux-$assign(mac_addr)"
set conf(mac_from_mod) 1

#
# AFS XML parser data and routines
#
set afs_token ""
set afs_token_stack [list]

set afs_value(dsn) ""

#
# handle data from AFS Get
#
proc afs_cdata {data args} {
	global afs_value
	global afs_token

	append afs_value($afs_token) "$data"
}

proc afs_elem_start {name attlist args} {
	global afs_value
	global afs_token
	global afs_token_stack

	lappend afs_token_stack $afs_token
	set afs_token $name
	set afs_value($afs_token) ""
}

proc afs_elem_end {name args} {
	global afs_token_stack
	global afs_token

	set afs_token_stack [lrange $afs_token_stack 0 end-1]
	set afs_token [lindex $afs_token_stack end]
}

#
# read assign() values from AFS
#
proc serial_get {} {
	global afs
	global afs_dir
	global afs_data
	global afs_err
	global afs_value
	global afs_key
	global afs_header
	global afs_offline
	global afs_used_dir
	global afs_file
	global afs_temp
	global assign
	global err
	global curl
	global ca_bundle
	global conf

	if {$assign(serial) != ""} {
		puts "Serial number already assigned.  Skipping AFS get\n"
		return
	}

	set afs_value(dsn) ""
	set afs_value(public-key) ""
	set afs_value(mac) ""

	#
	# If a MAC address was not assigned, request it from the service.
	#
	set post_arg "?count=1"
	if {$assign(mac_addr) == "" && !$conf(mac_from_mod)} {
		append post_arg "&mac=true"
	}

	if {$afs_offline} {
		#
		# Find offline serial number file.
		# Use the first one found by glob (will be lowest sn).
		# Setting afs_data will cause file to be deleted below.
		#
		puts "Looking up AFS info\n"
		set files [glob -type {f r} -nocomplain $afs_dir/*]
		if {![llength $files]} {
			error "Out of serial numbers in $afs_dir." "" \
				$err(serial_get)
		}

		set afs_data [lindex $files 0]
		puts "Using $afs_data\n"

		#
		# afs_data will be removed.
		# make a copy in case we don't end up using the DSN
		# afs_file will be the original file name
		# afs_temp is the temporary copy.
		#
		set afs_file $afs_data
		file mkdir $afs_used_dir
		set afs_temp $afs_used_dir/[file tail $afs_data]
		# puts "copying $afs_data to $afs_temp\n"
		file copy "$afs_data" "$afs_temp"
	} else {
		puts "\nRequesting AFS info\n"

		if [catch {
			exec "$curl" -X POST -o "$afs_data" \
				--stderr "$afs_err" \
				--dump-header "$afs_header" \
				-d "" -H "Content-Type: application/xml" \
				-E "$afs_key" \
				--cacert $ca_bundle \
				"$afs/certs.xml$post_arg"
			
		}] {
			file delete "$afs_data" "$afs_err" "$afs_header"
			error "AFS request for new serial number failed." "" \
				$err(serial_get)
		}

		#
		# Check HTTP header
		#
		set status [http_status "$afs_header"] 
		if {$status != "OK"} {
			set err_code $err(serial_get)
			if {$status == "nodev"} {
				set err_code $err(serial_none)
			}
			file delete "$afs_data" "$afs_err" "$afs_header"
			error "AFS request for new serial number failed: \
				$status " "" $err_code
		}
	}

	#
	# parse XML data
	#
	set parser [::xml::parser \
		-characterdatacommand afs_cdata \
		-elementstartcommand afs_elem_start \
		-elementendcommand afs_elem_end]

	if [catch {set fd [open "$afs_data" r]}] {
		file delete "$afs_data" "$afs_err" "$afs_header"
		error "read of new serial number failed:\ 
			empty data" "" $err(serial_get)
	}

	$parser parse [read $fd]
	close $fd

	#
	# use parse results
	#
	if {$afs_value(dsn) == "" || $afs_value(public-key) == ""} {
		error "AFS request for new serial number failed" "" \
			$err(serial_parse)
	}
	set assign(serial) $afs_value(dsn)

	if {$conf(mac_from_mod)} {
		if {$assign(mac_addr) != ""} {
			error "--mac parameter not supported for this model"
			    "" $err(serial_no_mac)
		}
	} elseif {$assign(mac_addr) == ""} {
		if {$afs_value(mac) == ""} {
			error "no MAC address provided" "" $err(serial_no_mac)
		}
		set assign(mac_addr) [regsub -all : $afs_value(mac) ""]
	}
	set assign(public-key) $afs_value(public-key)

	file delete "$afs_data" "$afs_err" "$afs_header"
}

#
# Convert key to different RSA format
#
proc key_conv {} {
	global assign
	set fd ""

	set key_temp "/tmp/key-in.[pid]"
	set out_temp "/tmp/key-out.[pid]"
	puts "temp files $key_temp $out_temp"

	if [catch {set fd [open "$key_temp" "CREAT RDWR TRUNC"]}] {
		error "open of key conversion file $key_temp failed"
	}
	puts -nonewline $fd $assign(public-key)
	close $fd

	exec util/rsa_key_conv $key_temp $out_temp
	if [catch {exec rsa_key_conv $key_temp $out_temp}] {
		error "exec of rsa_key_conv failed"
	}

	if [catch {set fd [open "$out_temp" "RDONLY"]}] {
		file delete "$out_temp"
		error "open of key conversion result failed"
	}
	
	set assign(public-key) [read $fd]
	close $fd
}

proc config_write {} {
	global assign
	set fd "" 

	set out_file "config.$assign(serial)"

	if [catch {set fd [open "$out_file" "CREAT RDWR TRUNC"]}] {
		file delete "$out_file"
		error "open of config file $out_file failed"
	}

	set key [json::write string $assign(public-key)]

	puts $fd "{
		\"config\": {
			 \"id\": {
				\"dsn\": \"$assign(serial)\",
				\"model\": \"$assign(model)\",
				\"rsa_pub_key\": $key
			}
		}
	}"
	close $fd
}

#
# Update log file
#
proc log_ayla {status errcode model serial mac mfg_model mfg_serial {msg ""}} {
	global log_file
	global assign
	global err

	if {![regexp "^\[0-9\]+$" $errcode]} {
		set errcode $err(unknown)
	}

	set time [clock seconds]
	set timestamp "[clock format $time -gmt 1 \
		-format "20%y/%m/%d %T UTC"]"

	#
	# Comma-separated-values (CSV) log entry.
	# The first field is a format designator in case we want to
	# change it later or have multiple formats.
	#
	set entry "2,$time,$timestamp,$status,$errcode,$model,$serial,$mac"
	set entry "$entry,$mfg_model,$mfg_serial,$assign(stm32_sig),$msg"
	puts "LOG: $entry"
	if [catch {
		set fd [open $log_file a]
		puts $fd $entry
		close $fd
	} rc errinfo ] {
		puts "log $log_file write error code $rc\n"
		puts "log $log_file write error info \
			[dict get $errinfo -errorinfo]"
	}
	# log_afs $entry
}

serial_get
# key_conv
config_write

if {$assign(mac_addr) == ""} {
	set assign(mac_addr) "022233445566"
}

log_ayla label 0 $assign(model) $assign(serial) $assign(mac_addr) \
	$assign(mfg_model) $assign(mfg_serial)
