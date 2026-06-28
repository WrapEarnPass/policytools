#!/bin/bash
#Copyright (C) 2026 WrapEarnPass
#Creative work licensed under CC BY-NC-SA 4.0
if [ -z ${_POLICYTOOL_LIB} ]; then
	. policytool.bash.lib
fi

#generate-te from allow

function generate-te () {
	_allow="$1" #the actual file
	_source_name="$2" #the friendlynamery
	#ensure that source file doesnt mix and match source types.
	sanity-test "$_allow"
	#pull the TYPES CLASSES AND ALLOWS from $_allow
	declare -A _TYPES
	declare -A _CLASSES
	declare -A _PERMS
	while IFS=' }:{;' read _nil _source_type _target_type _class _perm; do
		if [ -n "$_source_type" ]; then
		_TYPES[${_source_type}]=""
		_TYPES[${_target_type}]=""
		_CLASSES[${_class}]=${_CLASSES[${_class}]}" "$_perm
		_address=${_target_type}:${_class}
		_PERMS[${_address}]=${_PERMS[${_address}]}" "$_perm
		fi
	done < "$_allow"
	
	#self is a reserved type, don't declare it
	unset _TYPES["self"]
	
	#now _PERM should have all the perms required for each s-t-c, but
	# the perms themselves may be duperatededed.
	declare -A _permlist
	for _item in ${!_PERMS[@]} ; do
		_permlist=()
		for _cleaned in ${_PERMS[${_item}]}; do 
			if [ "$_cleaned" != "};" ] && [ "$_cleaned" != " " ]; then 
				_permlist[${_cleaned}]=""
			fi
		done;
		_PERMS[${_item}]=""
		for _cleaned in ${!_permlist[@]} ; do 
			_PERMS[${_item}]=${_PERMS[${_item}]}" "$_cleaned
		done;
	done
	
	# also cleanup _CLASSES
	declare -A _permlist
	for item in ${!_CLASSES[@]} ; do
		_permlist=()
		for _cleaned in ${_CLASSES[${item}]}; do 
			if [ "$_cleaned" != "};" ] && [ "$_cleaned" != " " ]; then 
				_permlist[${_cleaned}]=""
			fi
		done;
		_CLASSES[${item}]=""
		for _cleaned in ${!_permlist[@]} ; do 
			_CLASSES[${item}]=${_CLASSES[${item}]}" "$_cleaned
		done;
	done
		
	#initialize .ver
	if [ ! -f "$_DIR/${_source_name}.ver" ] ; then
		echo 0 >  "$_DIR/${_source_name}.ver"
	fi
	_ver=$(cat "$_DIR/${_source_name}.ver")
	echo "1.0 + ${_ver}"| bc > "$_DIR/${_source_name}.ver"

	echo "writing ${_source_name}.te"

	#header
	echo "module ${_HOST}_${_source_name} $(cat "$_DIR/${_source_name}.ver");

	require {" > "${_DIR}/${_HOST}_${_source_name}.te"

	#types (both source and target)
	##	type dpkg_script_t;
	for _item in ${!_TYPES[@]} ; do
		echo "	type ${_item};" >> "${_DIR}/${_HOST}_${_source_name}.te"
	done

	#classes and permissions
	##class service { start status stop };
	for _item in ${!_CLASSES[@]} ; do
		echo "	class ${_item} {${_CLASSES[${_item}]} };" >> "${_DIR}/${_HOST}_${_source_name}.te"
	done
	#close require
	echo "}" >> "${_DIR}/${_HOST}_${_source_name}.te"

	#dump allows
	##allow xdm_t kernel_t:dbus send_msg;
	cat "$_allow" >> "${_DIR}/${_HOST}_${_source_name}.te"
}
