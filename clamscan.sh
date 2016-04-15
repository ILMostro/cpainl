#!/bin/bash
# Author: Chris James
# With additions by: Ben Purcell
# Scan public_html directories for malware using ClamAV

DEBUG=false
QUIET=false

TMP_FOLDER=/root/tmp
LOCKFILE=$TMP_FOLDER/clamscan.lock

CLAMSCAN_ROOT_PATH="false"

CLAMAV_ARGS="-i -r --scan-mail=no --scan-pe=no --scan-ole=no --scan-pdf=no --block-encrypted=yes --max-filesize=10M --max-recursion=200 --max-dir-recursion=200 --bytecode-timeout=10"

SCANS_DIR="/root/clamscans"


# Create helper functions for exit trap/cleanup

declare -a on_exit_items

function on_exit()
{
  for i in "${on_exit_items[@]}"
  do
    debug_echo "on_exit: $i"
    eval $i
  done
}

function add_on_exit()
{
  local n=${#on_exit_items[*]}
  on_exit_items[$n]="$*"
  if [[ $n -eq 0 ]]; then
    debug_echo "Setting trap: $*"
    trap on_exit EXIT
  fi
}


# Echoing helper functions

print_red() {
  echo -e "\e[1;31m$1\e[0m";
}

print_green() {
  if ! $QUIET; then
    echo -e "\e[1;32m$1\e[0m";
  fi
}

error() {
  echo -e >&2 "\e[1;31m$1\e[0m";
  exit 1;
}

debug_echo() {
  if $DEBUG; then
    echo "DEBUG: $1";
  fi
}

echo_n() {
  if ! $QUIET; then
    echo -n $1;
  fi
}

echo_e() {
  if ! $QUIET; then
    echo -e $1;
  fi
}


# Check if last command failed

check_if_fail() {
  if [ $1 -eq 0 ]; then
    print_green "OK"
  else
    print_red "FAIL, exit code $?"
  fi
}


# If mtime is specified, find files modified in past x days

mtime_check() {
  if [ "$MTIME_DAYS" -ne "0" ]; then
    local FILES_MODIFIED=$(find $* -type f -mtime -$MTIME_DAYS)
    echo -e "$FILES_MODIFIED"
  else
    echo -e "$*"
  fi
}


ctime_check() {
    if [ "$MTIME_DAYS" -ne "0" ]
    then
	local FILES_MODIFIED=$(find $* -type f -ctime -$MTIME_DAYS)
	echo -e "$FILES_MODIFIED"
    else
	echo -e "$*"
    fi
}

# Get directories/temp files to scan for comma seperated user list

get_user_directories_to_scan() {
  USERS_DOCROOTS=""
  for USER in $USERS; do
    local DOCROOT=$(cat /etc/httpd/conf/httpd.conf | grep "$USER" -2 | grep DocumentRoot | awk '{print $2}' | sort | uniq)
    USERS_DOCROOTS="$USERS_DOCROOTS $DOCROOT"
  done

  local DOCROOTS_TO_SCAN=$(get_docroots_to_scan $USERS_DOCROOTS)

  if [ "$MTIME_DAYS" -ne "0" ]; then
    TMP_FILES_OWNED_BY_USER=$(find /tmp -type f -user $USER -mtime -$MTIME_DAYS)
  else
    TMP_FILES_OWNED_BY_USER=$(find /tmp -type f -user $USER)
  fi
  local TO_SCAN="$(ctime_check $DOCROOTS_TO_SCAN) $TMP_FILES_OWNED_BY_USER"

  write_what_to_scan_file $TO_SCAN
}


get_all_directories_to_scan() {
  local ALL_DOCROOTS=$(grep DocumentRoot /usr/local/apache/conf/httpd.conf | awk '{print $2}' | sort | uniq)
  ALL_DOCROOTS="$ALL_DOCROOTS /tmp"
  local TO_SCAN=$(ctime_check $(get_docroots_to_scan $ALL_DOCROOTS))

  write_what_to_scan_file $TO_SCAN
}


# Get all document roots but discard any which are already contained in another

get_docroots_to_scan() {
  DOCROOTS_TO_SCAN=$*

  local UNIQ_DOCROOTS
  local FIRST_DOCROOT=true

  local DOCROOT
  for DOCROOT in $DOCROOTS_TO_SCAN; do
    if $FIRST_DOCROOT; then
      UNIQ_DOCROOTS=$DOCROOT
      FIRST_DOCROOT=false
    else
      local PREV_DOCROOT;
      local UNIQUE=true
      for PREV_DOCROOT in $UNIQ_DOCROOTS; do
        if [[ "$DOCROOT" == "$PREV_DOCROOT"* ]]; then
          UNIQUE=false
        fi
      done
      if $UNIQUE; then
        UNIQ_DOCROOTS="$UNIQ_DOCROOTS $DOCROOT"
      fi
    fi
  done;

  # return
  echo $UNIQ_DOCROOTS
}


# Create file which contains list of files & directories to scan

write_what_to_scan_file() {
  local LIST=$*

  # Create temporary file for document root directories to be scanned
  WHAT_TO_SCAN_FILE="$TMP_FOLDER/files.`date +%s`"
  add_on_exit rm -f $WHAT_TO_SCAN_FILE
  touch $WHAT_TO_SCAN_FILE 

  for i in $LIST; do
    echo $i >> $WHAT_TO_SCAN_FILE
  done

  debug_echo "Scanning: $(cat $WHAT_TO_SCAN_FILE)"
}


# Install maldet from source

install_maldet() {
  wget -N http://files.wiredtree.com/misc/maldet/maldetect-current.tar.gz -P $TMP_FOLDER
  tar xzf $TMP_FOLDER/maldetect-current.tar.gz -C $TMP_FOLDER
  add_on_exit rm -rf $TMP_FOLDER/maldetect-*
  cd $TMP_FOLDER/maldetect-*
  $TMP_FOLDER/maldetect-*/install.sh
}


# Install maldet if it is not installed and/or update it

setup_maldet() {
  local USE_MALDET_DEFS=true
  echo_n "Checking for maldet..."
  if ! type maldet > /dev/null 2>&1; then
    print_red "FAIL"
    echo_n "Maldet not found, installing..."
    install_maldet > /dev/null 2>&1
    if ! type maldet > /dev/null 2>&1; then
      print_red "FAIL"
      print_red "WARNING: Maldet could not be installed, will not use maldet malware definitions."
      USE_MALDET_DEFS=false
    else
      print_green "OK"
    fi
  else
    print_green "OK"
    echo_n "Updating maldet..."
    maldet -d > /dev/null 2>&1
    check_if_fail $?
    echo_n "Updating maldet definitions..."
    rm -rf /usr/local/maldetect/sigs/*
    echo 0 > /usr/local/maldetect/sigs/maldet.sigs.ver
    local MALDET_DEF_UP=$(maldet -u)
    if [[ "$MALDET_DEF_UP" = *"latest signature set already installed" ]] |
       [[ "$MALDET_DEF_UP" = *"signature set update completed"* ]] ; then
      check_if_fail 0
    else
      check_if_fail $?
    fi
  fi

  if [ $USE_MALDET_DEFS ]; then
    SIGNATURE_DBS="$SIGNATURE_DBS -d /usr/local/maldetect/sigs"
  fi
}


# Check for ClamAV

check_for_clamav() {
  CPANEL_1140=false
  CLAMAV_INSTALLED=false

  CPANEL_VERSION=$(/usr/local/cpanel/cpanel -V | sed 's/11.//' | awk -F. '{print $1}')
  if [ $CPANEL_VERSION -ge 40 ]; then
    CPANEL_1140=true
  fi

  if type /usr/bin/clamscan > /dev/null 2>&1; then
    CLAMAV_INSTALLED=true
  fi

  if ! $CPANEL_1140 && ! $CLAMAV_INSTALLED; then
    print_red "FAIL"
    error "ERROR: clamscan not found. Install it first using the WHM -> Manage Plugins."
  fi
}


# Try to install ClamAV from RPMS if possible

install_clamav() {
  if type /usr/bin/clamscan > /dev/null 2>&1; then
    CLAMSCAN_ROOT_PATH=/usr
  fi

  if type /usr/local/cpanel/3rdparty/bin/clamscan > /dev/null 2>&1; then
    CLAMSCAN_ROOT_PATH=/usr/local/cpanel/3rdparty
    chown -R clamav. /usr/local/cpanel/3rdparty/share/clamav/
  fi

  if [ $CLAMSCAN_ROOT_PATH == "false" ]; then
    CPANEL_VERSION=$(/usr/local/cpanel/cpanel -V | sed 's/11.//' | awk -F. '{print $1}')
    if [ $CPANEL_VERSION -ge 40 ]; then
      echo "Installing ClamAV RPM...";
      /scripts/update_local_rpm_versions --edit target_settings.clamav installed
      /usr/local/cpanel/scripts/check_cpanel_rpms --fix
      chown -R clamav. /usr/local/cpanel/3rdparty/share/clamav/

      if type /usr/local/cpanel/3rdparty/bin/clamscan > /dev/null 2>&1; then
        CLAMSCAN_ROOT_PATH=/usr/local/cpanel/3rdparty
        print_green "OK"
      else
        print_red "FAIL"
        error "ERROR: ClamAV RPMs could not be installed, try installing through the WHM -> Manage plugins."
      fi
    else
      print_red "FAIL"
      error "ERROR: clamscan not found. Install it first using the WHM -> Manage Plugins."
    fi
  fi

  # Clamav signatures location, maldet sigs are also added later if it's installed/can be installed
  SIGNATURE_DBS="-d $CLAMSCAN_ROOT_PATH/share/clamav/"
}

update_clamav() {
  # install/update ClamAV
  echo_n "Checking for clamscan..."
  if ! type "$CLAMSCAN_ROOT_PATH/bin/clamscan" > /dev/null; then
    print_red "FAIL"
    error "ERROR: clamscan not found. Install it first using the WHM -> Manage Plugins.";
  else
    print_green "OK"
    echo_n "Updating ClamAV definitions..."
    $CLAMSCAN_ROOT_PATH/bin/freshclam --quiet
    check_if_fail $?
  fi
}


# Prompt for options when run interactively

prompt_for_params() {
  TICKET_ID=""
  while [ -z $TICKET_ID ]; do
    echo -e "Ticket ID? \c"
    read TICKET_ID
    if [ -z $TICKET_ID ]; then
      print_red "You must enter a ticket ID."
    fi
  done

  echo -e "Mail to [s]upport, [a]buse, or [n]one: \c"
  local MAIL_TO_CHOICE
  read MAIL_TO_CHOICE
  case "$MAIL_TO_CHOICE" in
    s | S )
    MAIL_TO="support@wiredtree.com" ;;
    a | A )
    MAIL_TO="abuse@wiredtree.com" ;;
    n | N )
    MAIL_TO="" ;;
    * )
    MAIL_TO="support@wiredtree.com" ;;
  esac

  echo -e "CC to who at wiredtree.com (e.g. chris), leave blank for no-one: \c"
  local CC_TO_USER
  read CC_TO_USER
  if [ -n "$CC_TO_USER" ]; then
    CC_TO_USER=$(echo "$CC_TO_USER" | cut -d@ -f1);
    CC_TO="$CC_TO_USER@wiredtree.com"
  else
    CC_TO=""
  fi


  #Send customer a copy of the results? y/n:
  #Customer Email Address? (user@example.org):

  echo -e "The next option will use the ticket number earlier in \
a formatted message. If you didn't set a real ticket id, don't say yes."
  echo -e "Send customer a copy of the results? y/n: \c"
  read SEND_CUSTOMER_EMAIL
  if [[ $(echo "$SEND_CUSTOMER_EMAIL" | head -c 1) == "y" ]]; then
      SEND_CUSTOMER_EMAIL=true
      CLIENT_EMAIL=""
      while [ -z $CLIENT_EMAIL ]; do
	  echo -e "Customer Email Address? (user@example.org) \c"
	  read CLIENT_EMAIL
	  if [ -z $CLIENT_EMAIL ]; then
	      print_red "You must enter an email address."
	  fi
      done
    else
      SEND_CUSTOMER_EMAIL=false
  fi

  # this has a bug. Why is it setting MAIL_RESULTS true when mail_to is none and cc_to was blank?
  if [ -z "$MAIL_TO" ] && [ -z "$CC_TO" ]; then
    MAIL_RESULTS=false
  else
    MAIL_RESULTS=true
  fi

  debug_echo "Ticket ID: $TICKET_ID"
  debug_echo "Mailing to: $MAIL_TO"
  debug_echo "CC-ing to: $CC_TO"
  echo -e "Scan which users (e.g. chris,nick,sam), leave blank for all: \c"
  read USERS
  if [ -n "$USERS" ]; then
    parse_users $USERS
  fi
}


# Email scan results

mail_results() {
  local SUBJECT=""
  if [ $1 -eq 0 ]; then
    SUBJECT="Clamscan done"
  else
    SUBJECT="Clamscan FAILED"
  fi

  SUBJECT="$SUBJECT on `hostname`"
  if [ -n "$TICKET_ID" ]; then
    SUBJECT="$SUBJECT for $TICKET_ID"
  fi

  MAIL_TO_ARGS=""
  # if there's a cc but no mail, set mail = cc
  if [ -z "$MAIL_TO" ] && [ -n "$CC_TO" ]; then
    MAIL_TO=$CC_TO
    CC_TO=""
  fi

  if [ -n "$CC_TO" ]; then
    MAIL_TO_ARGS="$MAIL_TO_ARGS -c $CC_TO"
  fi
  if [ -n "$MAIL_TO" ]; then
    MAIL_TO_ARGS="$MAIL_TO_ARGS $MAIL_TO"
  fi

  debug_echo "mail -v - s $SUBJECT $MAIL_TO_ARGS"
  cat "$SCAN_SAVE_FILE" | mail -v -s "$SUBJECT" $MAIL_TO_ARGS
}


# Do the needful

scan() {
  SCAN_SAVE_FILE="$SCANS_DIR/scan.`date +%s`"
  if [ -n $TICKET_ID ]; then
    SCAN_SAVE_FILE="$SCAN_SAVE_FILE.$TICKET_ID"
  fi

  if $QUIET; then
    CLAMAV_ARGS="$CLAMAV_ARGS --quiet"
  fi
  CLAMAV_ARGS="$CLAMAV_ARGS $SIGNATURE_DBS -f $WHAT_TO_SCAN_FILE -l $SCAN_SAVE_FILE"
  print_green "Scan started!"
  debug_echo "$CLAMSCAN_ROOT_PATH/clamscan $CLAMAV_ARGS"
  echo_e "\n------------ SCAN HITS -------------\n"
  mkdir -p $SCANS_DIR
  $CLAMSCAN_ROOT_PATH/bin/clamscan $CLAMAV_ARGS
  print_green "Scan complete! Results saved in $SCAN_SAVE_FILE"
  ln -sf $SCAN_SAVE_FILE $SCANS_DIR/scan.last
}


# Quarantine the results

words() {
	echo $#
}

depth() {
(
	IFS='/'
	echo $(( $(words $1) -1 ))
) }

quarantine() {
	FILE=$1
	SCAN_FILE=$( echo ${2:-$(date +%s)} | awk -F'/' '{print $NF }' )
	DIR=$( echo $1 | cut -d/ -f1-$(depth $FILE) )
	mkdir -p "/root/abuse/${SCAN_FILE}/${DIR}"
	mv  "$FILE" "/root/abuse/${SCAN_FILE}/${DIR}"
}

quarantine_results() {
(
	IFS=$(printf '\n\b')
	for MALFILE in $(awk -F: '/FOUND/ {print $1}' $SCAN_SAVE_FILE);
	do
		quarantine $MALFILE $SCAN_SAVE_FILE
	done
) }

# View and optionally quarantine results: not yet finished

ensure_unique()
{
    if [ -f $LOCKFILE ]
    then
	error "ERROR: $LOCKFILE detected. Scan running as PID $(cat $LOCKFILE). Exiting."
    fi
}


create_lockfile()
{
    ensure_unique
    # write our PID to the lock
    echo $$ > $LOCKFILE
}

remove_lockfile()
{
    rm -f $LOCKFILE
}

# Get/check lock so we don't run more than one scan at once

get_lock() {
  CLAMSCAN_PIDS=$(pgrep -f "/bin/bash \./clamscan.sh")
  if [[ $(echo $CLAMSCAN_PIDS | wc -w) -gt 1 ]] ; then
    error "ERROR: Found clamscan in process list, are we already scanning?"
  fi

  create_lockfile

  add_on_exit remove_lockfile

}

# Print command line usage

print_usage(){
  echo -e "Usage:\n $0 [options]\n"
  echo -e "Options:"
  echo -e "-i, --interactive\t Prompt for scanning arguments interactively."
  echo -e "-a, --all\t\t Scan all users."
  echo -e "-u, --users [users]\t Scan comma seperated users (e.g. chris,nick,sam)."
  echo -e "-m, --mail [address]\t Mail results to address."
  echo -e "-c, --cc [address]\t CC results to address(es), list should be comma seperated list of addresses."
  echo -e "-C, --client [address]\t Send formatted copy to the client."
  echo -e "-t, --mtime [days]\t Only scan files modified in last x days."
  echo -e "-q, --quarantine [file]\t Quarantine results found in file. (defaults to last scan)"
  echo -e "-Q, --autoquarantine\t Automatically quarantine results in this scan."
  echo -e "-e, --view [file] \t View and optionally quarantine results found in file. (defaults to last scan)"
  echo -e "-h, --help\t\t Print this help information."
  echo ""
  exit 1
}


# Parse given user list

parse_users() {
  if [ -z "$1" ]; then
    error "ERROR: No users provided."
  fi

  USERS=$(echo $1 | sed "s/,/ /g")
  debug_echo "Scanning users: $USERS"
}


# Parse command line arguments

parse_args() {
  INTERACTIVE=false
  SCAN_ALL=false

  # no arguments given, assuming interactive mode
  if [ $# -eq 0 ]; then
    INTERACTIVE=true
  fi
  while [ $# -ne 0 ]; do
    case "$1" in
      --interactive | -i )
      INTERACTIVE=true ;;
      --users | -u )
      shift # remove already read argument
      parse_users $1 ;;
      --all | -a )
      SCAN_ALL=true ;;
      --mail | -m )
      shift
      MAIL_RESULTS=true
      MAIL_TO=$1 ;;
      --cc | -c )
      shift
      MAIL_RESULTS=true
      CC_TO=$1 ;;
      --mtime | -t )
      shift
      MTIME_DAYS=$1 ;;
      --client | -C )
      shift
      SEND_CUSTOMER_EMAIL=true
      CLIENT_EMAIL=$1 ;;
      --autoquarantine | -Q )
      AUTOQUARANTINE=true ;;
      --quarantine | -q )
      shift
      QUARANTINE=true
      SCAN_SAVE_FILE="${SCANS_DIR}/${1:-scan.last}" ;;
      --view | -e )
      shift
      VIEW=true
      SCAN_SAVE_FILE="${SCANS_DIR}/${1:-scan.last}" ;;
      --help | -h | * )
      print_usage ;;
    esac
    shift
  done
}
 
client_email() {
    SUBJECT="WiredTree malware scan results requested in $TICKET_ID"
    MAIL_TO_ARGS=" $CLIENT_EMAIL"

    cat <<EOF > $TMPDIR/client_email.txt
Hi there,

Do not reply back to this message. This is an automated email from WiredTree's malware detection script that just finished running on your server. You requested a copy of this report in Grove Ticket $TICKET_ID.

This is a copy of your most recent clamscan on your cPanel user's files. This report contains any hits of any known malware in your site code files. Most account level compromises are due to insecure site software (Such as outdated WordPress, Joomla, Drupal, etc). Ensuring that your site code software is up to date, along with all installed plugins, themes and third party addons and making sure that your local computers are virus free, are key steps to ensuring that this doesn't happen again.

If you just replace the files in question without updating your site code, plugins, themes, etc, along with changing all of your account level passwords, this issue will most likely happen again.

Again, this is an automated message. Do not reply back to it. Please reply back to Grove ticket $TICKET_ID if you need help.

Thanks! WiredTree Support


EOF
    # send the message, with the results inline
    cat $TMPDIR/client_email.txt "$SCAN_SAVE_FILE" | mail -v -s "$SUBJECT" $MAIL_TO_ARGS
    # cleanup the message file.
    rm -f $TMPDIR/client_email.txt

}



# This is where we begin...

init() {
  # Bail if not running as root
  if [ "$(id -u)" != "0" ]; then
    error "ERROR: This script must be run as root."
  fi

  parse_args $@

  if [ $QUARANTINE ]
  then
    quarantine_results
    exit 0
  fi

  check_for_clamav

  mkdir -p $TMP_FOLDER

  get_lock

  if [ -z "$MTIME_DAYS" ]; then
    MTIME_DAYS=0
  fi

  if $INTERACTIVE; then
    prompt_for_params
    if [ -n "$USERS" ]; then
      get_user_directories_to_scan
    else
      get_all_directories_to_scan
    fi
  else
    # run w/ arguments
    if $SCAN_ALL; then
      get_all_directories_to_scan
    else
      get_user_directories_to_scan
    fi
  fi

  install_clamav
  update_clamav
  setup_maldet

  scan

  if [ $AUTOQUARANTINE ]; then
    quarantine_results
  fi

  if [ "$MAIL_RESULTS" == "true" ]; then
    # $? is return value of clamscan
    mail_results $?
  fi

  if [ "$SEND_CUSTOMER_EMAIL" == "true" ]; then
      client_email $?
  fi
}

init $@
