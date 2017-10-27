#!/bin/sh

[ -r /etc/debian_version ] && debian=1
[ -r /etc/lsb-release ] && grep -q Ubuntu /etc/lsb-release && debian=1

if test x$debian = x1; then
  list_command="dpkg -l |grep -e rtSupCP -e cprocsp|awk '{print \$2}'"
  del_command="dpkg -P"
else
  list_command="rpm -qa |grep -e rtSupCP -e cprocsp"
  del_command="rpm -e --allmatches"
fi

pkglist=`eval "$list_command"`
compat_pkg=`echo "$pkglist" | grep compat || echo 'NULL'`
rdr_pkgs=`echo "$pkglist" | grep rdr-[0-9]`
base_pkg=`echo "$pkglist" | grep base | grep -v ssl`
pkglist=`echo "$pkglist" | grep -vx "$base_pkg" | grep -v "$compat_pkg"`
for rdr_pkg in $rdr_pkgs; do pkglist=`echo "$pkglist" | grep -vx "$rdr_pkg"`; done
if test -n "$pkglist"
then
  $del_command $pkglist
fi
if test -n "$rdr_pkgs"; then $del_command $rdr_pkgs; fi
if test -n "$base_pkg"; then $del_command $base_pkg; fi
if test "$compat_pkg" != "NULL"; then $del_command $compat_pkg; fi

exit $?
