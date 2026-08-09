#!/bin/bash
#Copyright (C) 2026 WrapEarnPass
#Creative work licensed under CC BY-NC-SA 4.0

if [ -z ${_POLICYTOOL_LIB} ]; then
	. policytool.bash.lib
fi

#sort/uniq + dedup for allows files.
function uniq-allows (){
	#read from _allow
	_allow="$1"
	#ensure that source file doesnt mix and match source types.
	sanity-test "$_allow"
	#echo "uniq called with $_allow"
	_TMP=$(mktemp)
	declare -A _PERMS
	_source_type=""
	while IFS=' }:{;' read _nil _source_read _target_type _class _perm; do
			if [ -n "$_nil" ]; then 
				_address="${_target_type}:${_class}"
				_source_type="$_source_read" 
				_PERMS["$_address"]=${_PERMS[${_address}]}" "${_perm}
			fi
	done < "$_allow"

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
		#write to _TMP
		echo "allow ${_source_type} ${_item} {${_PERMS[${_item}]} };" >> "$_TMP"
	done

	#then mv _TMP back to _allow
	sort -u "$_TMP" > "$_allow"
	rm "$_TMP"
}
