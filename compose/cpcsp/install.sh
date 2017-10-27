#!/bin/bash

function check_fail(){
if test $1 -ne 0; then
 if test $UID -eq 0; then
  echo "  Installation failed. LSB package may not be installed.
  Install LSB package and reinstall CryptoPro CSP. If it does not help, please 
  read installation documentation or contact the manufacturer: support@cryptopro.ru."
 fi
 exit $1
fi	
}

show_help(){
  echo "
  using install.sh: 
  install.sh [arguments]:

  select [arguments] from:
  kc1 - install kc1 packages (by default)
  kc2 - install kc2 packages
"
}

enclosure=kc1
case $1 in
""|kc1)
  enclosure=kc1
;;
kc2)
  enclosure=kc2
;;
"-help")
  show_help
  exit 0
;;
"--help")
  show_help
  exit 0
;;
*)
  echo "usage: install.sh [kc1|kc2]"
  exit 1
;;
esac

cd `dirname $0`

[ -r /etc/debian_version ] && debian=1
[ -r /etc/lsb-release ] && grep -q Ubuntu /etc/lsb-release && debian=1

is_deb_release=0
if test x$debian = x1; then
  ls lsb-cprocsp-base*.deb > /dev/null 2>&1 && is_deb_release=1
  if test $is_deb_release -eq 1; then 
    type dpkg 1>/dev/null 2>&1
    if test $? -ne 0; then
      echo "You are trying to install debian packages on not debian package system" && exit 1
    fi
  fi
fi

/bin/sh ./uninstall.sh || exit $?

isarm=0
case `uname -m` in
x86_64|amd64)
  ARG=64
  if test $is_deb_release -eq 1; then
    arch=amd64
  else
    arch=x86_64
  fi
  ;;
armv7l|armv7)
  arch=noarch
  isarm=1
  ;;
ppc64)
  ARG=64
  arch=ppc64
  ;;
ppc64le)
  ARG=64
  arch=ppc64le
  ;;
*)
  if test $is_deb_release -eq 1; then
    arch=i386
  else
    arch=i486
  fi
  ;;
esac


if [ -f /etc/cp-release ]; then
   cat /etc/cp-release | grep Gaia > /dev/null
   isGaia=$((!$?))
   if [ "$isGaia" -eq 1 ]; then
      #GAiA OS
      rpm -i cprocsp-compat-gaia-1.0.0-1.noarch.rpm
   else
      #SPLAT OS
      rpm -i cprocsp-compat-splat-1.0.0-1.noarch.rpm
   fi
fi

if [ -f /etc/altlinux-release ]; then
  if test "$ARG" == "64"; then 
     bits="-64"
  fi
  rpm -i cprocsp-compat-altlinux${bits}-1.0.0-1.noarch.rpm
fi

if test $is_deb_release -eq 1; then
  if ! dpkg -s lsb-core > /dev/null 2>&1; then
    echo 'Warning: lsb-core package not installed - installing cprocsp-compat-debian.'
    echo 'If you prefer to install system lsb-core package then'
    echo ' * uninstall CryptoPro CSP'
    echo ' * install lsb-core manually'
    echo ' * install CryptoPro CSP again'
    dpkg -i cprocsp-compat-debian_1.0.0-1_all.deb || check_fail $?
  fi

  echo "Installing lsb-cprocsp-base_4.0.0-4_all.deb..."
  dpkg -i lsb-cprocsp-base_4.0.0-4_all.deb || check_fail $?
else
  echo "Installing lsb-cprocsp-base-4.0.0-4.noarch.rpm..."
  if test x$debian = x1; then
    if [ $isarm -eq 1 ]; then
      alien -kci cprocsp-compat-armhf-1.0.0-1.noarch.rpm || check_fail $?
    fi
    alien -kci lsb-cprocsp-base-4.0.0-4.noarch.rpm || check_fail $?
  else
    if [ $isarm -eq 1 ]; then
      rpm -i cprocsp-compat-armhf-1.0.0-1.noarch.rpm || check_fail $?
    fi
    rpm -i lsb-cprocsp-base-4.0.0-4.noarch.rpm || check_fail $?
  fi
fi

list="lsb-cprocsp-rdr lsb-cprocsp-capilite lsb-cprocsp-$enclosure cprocsp-curl"
if test $is_deb_release -eq 1; then
  for i in $list; do
    if test x$ARG = x64 && [ -e lsb-cprocsp-rdr-64_4.0.0-4_$arch.deb ]; then
      i="${i}-64"
    fi
    echo "Installing $i..."
    dpkg -i ${i}_4.0.0-4_$arch.deb || check_fail $?
  done
else
  for i in $list; do
    if test x$ARG = x64 && [ -e lsb-cprocsp-rdr-64-4.0.0-4.$arch.rpm ]; then
      i="${i}-64"
    fi
    echo "Installing $i..."
    if test x$debian = x1; then
      alien -kci $i-4.0.0-4.$arch.rpm || check_fail $?
    else
      rpm -i $i-4.0.0-4.$arch.rpm || check_fail $?
    fi
  done
fi
