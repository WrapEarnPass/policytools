#!/bin/bash
#Copyright (C) 2026 WrapEarnPass
#Creative work licensed under CC BY-NC-SA 4.0

#init libraries
if [ -z ${_POLICYTOOL_LIB} ]; then
	. policytool.bash.lib
fi

#argument processing
if [ -n "$1" ] ; then
	#given any argument assume help
cat << EOF
.run                                timestamp of last run
./disallows                         regex file of permissions to deny automatically
                                    disallow uses grep -E formatting for regex
./<SOURCE_TYPE_T>.allow             explicit permissions for <SOURCE_TYPE_T>
$_DIR/                              all policytool internal records
$_DIR/<SOURCE_TYPE_T>.allow         deduped allows to be written to .te files
$_DIR/<SOURCE_TYPE_T>.explode       used to compare allows to disallows
$_DIR/<SOURCE_TYPE_T>.prev          used to compare staged permissions to existing
$_DIR/<hostname>_<SOURCE_TYPE>.ver  type enforcement version record
$_DIR/<hostname>_<SOURCE_TYPE>.te   type enforcement file generated
$_DIR/<hostname>_<SOURCE_TYPE>.mod  policy module file generated
$_DIR/<hostname>_<SOURCE_TYPE>.pp   policy package file generated
./disable_dontaudit                 load policies with semodule -D
                                    delete the file to disable
Once policy packages are compiled, they are loaded and audit.log is truncated
EOF
	exit 0
fi

_header_sleep=0
#sanitycheck the disallows
if [ ! -f "./disallows" ]; then
	echo "WARNING: No disallows, everything will be approved."
	_header_sleep=1
elif [ "$(grep -cP '^$' ./disallows)" -gt "0"  ]; then
	echo "ERROR: disallows contains a blank line."
	exit 121
fi
#check the dontaudit
if [ -f "./disable_dontaudit" ]; then
	echo "WARNING: semodule to be invoked with -D"
	_header_sleep=1
	_disable_dontaudit=1
fi

#init functions
. explode-allows.bash
. uniq-allows.bash
. generate-te.bash


#Grab audit2allow -a
if [ "$_WHO" == "root" ] ; then
	#grab everything we know of
	audit2allow -a > audit.log
	#and ensure that journalctl is included.
	journalctl -b | grep avc |grep denied | sed -e 's/.*{\s\(.*\)\s}.*scontext=.*:.*:\(.*\):.*tcontext=.*:.*:\(.*\):.*tclass=\(.*\).*permissive.*/allow \2 \3:\4{ \1 };/g' | sort | uniq >> audit.log
fi

#allow time for warnings to show.
if [ "$_header_sleep" -gt "0" ] ; then
	sleep 5s
fi

#read the audit file and determine if there are any new allows
#if there are, push them into source-users
_skip_allow=0;
_skip_line=0;
while IFS=' }:{;' read _nil _source_read _target_type _class _perm; do
	if [ "$_nil" == "#=============" ]; then
		#skip section header
		continue
	fi
	if  [ "$_nil" == "#!!!!" ] && [ "$_perm" == "may have been overridden by an extended permission av rule" ]; then
		#skip override warning
		continue
	fi
	if  [ "$_nil" == "#!!!!" ] && [[ "$_perm" == "be allowed using the boolean"* ]]; then
		#skip single boolean advice
		continue
	fi
	if  [ "$_nil" == "#!!!!" ] && [ "$_perm" == "be allowed using one of the these booleans:" ]; then
		#skip multiple boolean advice
		_skip_line=1
		continue
	fi
	if [ "$_nil" == "#!!!!" ] && [ "$_perm" == "allowed in the current policy" ]; then
		#skip the next allow
		_skip_allow=1
		#skip the warning about already allowed
		continue
	fi
	if  [ "$_nil" == "#!!!!" ] && [[ "$_perm" == "a constraint violation"* ]]; then
		#skip the next allow as it is set but invalid
		_skip_allow=1
		#skip constraint warnings
		continue
	fi
	if  [ "$_nil" == "#Constraint" ] || [ "$_nil" == "#	constrain" ] || [ "$_nil" == "#	Possible" ] ; then
		#skip constraint warnings
		continue
	fi
	if [ "$_skip_line" -eq "1" ] && [ "$_nil" == "#" ]; then
		#we are in skip
		_skip_line=0
		continue
	fi
	if [ "$_skip_allow" -eq "1" ] && [ "$_nil" == "allow" ]; then
		#we are in skip
		_skip_allow=0
		continue
	fi
	if [ -n "$_nil" ] && [ "$_nil" == "allow" ]; then
		#we have a new actual permission
		if [[ $_perm == *"};" ]]; then
			#close the permission
			_perm="{ $_perm"
		fi
		if [[ $_perm != *";" ]]; then
			#close the permission
			_perm="${_perm};"
		fi
		#echo "$_nil $_source_read $_target_type:$_class $_perm"
		echo "$_nil $_source_read $_target_type:$_class $_perm" >> "$_DIR/$_source_read.allow"
	fi
done < audit.log


#disallow handling
#ensure new allows are tested against disallows
_allows=$(find "$_DIR" -type f -name '*.allow' -newer "$_RUN" )
for _allow in $_allows ; do
	#create explodes for global disallow processing
	explode-allows "$_allow"
	#remove global disallows from each source_user
	grep -vEf ./disallows "${_allow}.explode" 2>/dev/null > "$_allow"
done
#if disallows has been edited, go back and remove the new disallows from existing perms
if [ -f "./disallows" ] && [ "./disallows" -nt "$_RUN" ] ; then
	_allows=$(find "$_DIR" -type f -name '*.allow')
	for _allow in $_allows ; do
		#create explodes for global disallow processing
		echo "applying disallows on $_allow"
		explode-allows "$_allow"
		#remove global disallows from each source_user
		grep -vEf ./disallows "${_allow}.explode" 2>/dev/null > "$_allow"
	done
fi


#overrides
#this can't be done in new allows because an override may
#be created independently of a new allow
_allows=$(find . -maxdepth 1 -type f -name '*.allow' -newer "$_RUN" )
for _allow in $_allows ; do
	echo "overriding $_allow"
	#the overrides have been edited
	#sort-uniq the allows to allow for easier editing.
	uniq-allows "$_allow"
	#add new overrides to allows
	cat $_allow >> "$_DIR/$_allow"
	#uniq/sort the allow for easier reviewing
	uniq-allows "$_DIR/$_allow"
done
#add overrides to any newly generated allows too.
_allows=$(find "$_DIR" -maxdepth 1 -type f -name '*.allow' -newer "$_RUN" )
for _allow in $_allows ; do
	_override=$(basename ${_allow})
	if [ -f "$_override" ] ; then
		echo "overriding $_allow"
		#add new overrides to allows
		cat $_override >> "$_allow"
		#uniq/sort the allow for easier reviewing
		uniq-allows "$_allow"
	fi
done


#stash and compare .prev
#now we have all the changes, see if they are actually changes.
_allows=$(find "$_DIR" -maxdepth 1 -type f -name '*.allow' -newer "$_RUN" )
for _allow in $_allows ; do
	if [ -e "$_allow" ] && [ ! -s "$_allow" ]; then
		#nothing permitted
		rm "$_allow" "$_allow".prev "$_allow".explode &> /dev/null
		continue
	fi
	#sort-uniq the allows
	uniq-allows "$_allow"
	if [ -f "$_allow".prev ] ; then
		cmp -s "$_allow" "$_allow".prev
		_cmp=$?
		if [ "$_cmp" -eq "0" ] ; then
			#slag the allows to prevent processing
			touch -r "$_RUN" "$_allow"
		fi
	fi
	#stash the changes
	cp "$_allow" "$_allow".prev

done


#cleanup forbidden modules
#remove any modules that used to exist, but now do not.
_typeenforce=$(find "$_DIR" -maxdepth 1 -type f -name '*.te')
for _source_file in $_typeenforce ; do
	#_source_file should be <machinename>_<typename without _t>.te
	_allow="$(basename "$_source_file")"
	_allow=${_allow#"${_HOST}_"}
	_allow=${_allow%".te"}
	_allow="$_DIR/${_allow}_t.allow"
	if [ ! -f $_allow ] ; then
		echo -n "About to remove module $_source_file"
		read _wait_until

		#there are no permissions at all, purge
		_source_name=${_source_file%".te"}
		rm "${_source_name}".te "${_source_name}".mod "${_source_name}".pp  "${_source_name}".ver "${_allow}".explode "${_allow}".prev &> /dev/null
		_source_name="$(basename ${_source_name})"
		if [ "$_WHO" == "root" ] ; then
			semodule -l | grep -c "${_source_name}" &> /dev/null  && semodule -r "${_source_name}"
		else
			echo "get ROOT to semodule -r \"${_source_name}\""
		fi
	fi
done


#build .te files from generated allows
#we only want to generate files which were changed in this session
_allows=$(find "$_DIR" -maxdepth 1 -type f -name '*.allow' -newer "$_RUN" )
_new=""
_FAILBOAT=0
for _allow in $_allows ; do
	if [ -e "$_allow" ] && [ ! -s "$_allow" ]; then
		#nothing permitted
		rm "$_allow" "$_allow".prev "$_allow".explode &> /dev/null
		continue
	fi
	_source_name="$(basename "$_allow")"
	_source_name=${_source_name::-8}

	echo "$_source_name changed"
	generate-te "$_allow" "$_source_name"

	checkmodule -M -m "$_DIR/${_HOST}_${_source_name}.te" -o "$_DIR/${_HOST}_${_source_name}.mod"
	#if this failed, set _FAILBOAT=1
	if [ "$?" -gt "0" ] || [ "$_FAILBOAT" -gt "0" ]; then
		_FAILBOAT=1;
	fi

	#echo "semodule_package"
	semodule_package -o "$_DIR/${_HOST}_${_source_name}.pp" -m "$_DIR/${_HOST}_${_source_name}.mod"
	#if this failed, set _FAILBOAT=1
	if [ "$?" -gt "0" ] || [ "$_FAILBOAT" -gt "0" ]; then
		_FAILBOAT=1;
	fi
	#pass the semodule_package down the line.
	_new="$_new $_DIR/${_HOST}_${_source_name}.pp"
done

#echo "$_new"
#stop here if we are aboard the _FAILBOAT=1
if [ "$_FAILBOAT" -gt "0" ]; then
	echo "Unable to package semodule."
	exit 127
fi

if [ "$_WHO" == "root" ] && [ -n "$_new" ]; then
	#load policies
	if [ -z ${_disable_dontaudit} ]; then
		semodule -v -i $_new
	else
		echo "Loading modules with dontaudit_disabled"
		semodule -v -D -i $_new
	fi
	if [ "$?" -gt "0" ]; then
		echo "Unable to load semodules."
		exit 128
	fi

	#purge audit.log
	#truncate -s0 /var/log/audit/audit.log
	rm /var/log/audit/audit.log.* &>/dev/null
fi

#set runtime
echo "setting last run"
sleep 2s;
date +%s > "$_RUN"
