#!/bin/bash
#Copyright (C) 2026 WrapEarnPass
#Creative work licensed under CC BY-NC-SA 4.0

if [ -z ${_POLICYTOOL_LIB} ]; then
	. policytool.bash.lib
fi

#explode permissions for matching
function explode-allows (){
	#read from _allow
	_allow="$1"
	#ensure that source file doesnt mix and match source types.
	sanity-test $_allow
	#echo "explode called with $_allow"
	_TMP=$(mktemp)
	declare -A _PERMS
	_source_type=""
	while IFS=' }:{;' read _nil _source_read _target_type _class _perm; do
		if [ -n "$_nil" ] && [ "$_perm" != "};" ] && [ "$_perm" != " " ]; then 
			_source_type="$_source_read"
			_address="${_target_type}:${_class}"
			_PERMS[${_address}]="${_PERMS[${_address}]} ${_perm}"
		fi
	done < "$_allow"

	#now _PERM should have all the perms required for each s-t-c, but
	#the perms themselves may be duperatededed.
	declare -A _permlist
	for _item in ${!_PERMS[@]} ; do
		_permlist=()
		for _cleaned in ${_PERMS[${_item}]}; do 
			if [ "$_cleaned" != "};" ] && [ "$_cleaned" != " " ]; then 
				_permlist[${_cleaned}]=""
			fi
		done;
		for _cleaned in ${!_permlist[@]} ; do 
			echo "allow $_source_type $_item $_cleaned;" >> "$_TMP"
		done;
	done
	#mv tmp to explode
	sort -u "$_TMP" > "$_allow".explode
	#cleanup $_TMP
	rm "$_TMP"
}
