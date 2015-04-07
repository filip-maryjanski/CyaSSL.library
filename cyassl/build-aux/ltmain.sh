# Generated from ltmain.m4sh.

# ltmain.sh (GNU libtool) 2.2.6b
# Written by Gordon Matzigkeit <gord@gnu.ai.mit.edu>, 1996

# Copyright (C) 1996, 1997, 1998, 1999, 2000, 2001, 2003, 2004, 2005, 2006, 2007 2008 Free Software Foundation, Inc.
# This is free software; see the source for copying conditions.  There is NO
# warranty; not even for MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.

# GNU Libtool is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or
# (at your option) any later version.
#
# As a special exception to the GNU General Public License,
# if you distribute this file as part of a program or library that
# is built using GNU Libtool, you may include this file under the
# same distribution terms that you use for the rest of that program.
#
# GNU Libtool is distributed in the hope that it will be useful, but
# WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
# General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with GNU Libtool; see the file COPYING.  If not, a copy
# can be downloaded from http://www.gnu.org/licenses/gpl.html,
# or obtained by writing to the Free Software Foundation, Inc.,
# 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301, USA.

# Usage: $progname [OPTION]... [MODE-ARG]...
#
# Provide generalized library-building support services.
#
#     --config             show all configuration variables
#     --debug              enable verbose shell tracing
# -n, --dry-run            display commands without modifying any files
#     --features           display basic configuration information and exit
#     --mode=MODE          use operation mode MODE
#     --preserve-dup-deps  don't remove duplicate dependency libraries
#     --quiet, --silent    don't print informational messages
#     --tag=TAG            use configuration variables from tag TAG
# -v, --verbose            print informational messages (default)
#     --version            print version information
# -h, --help               print short or long help message
#
# MODE must be one of the following:
#
#       clean              remove files from the build directory
#       compile            compile a source file into a libtool object
#       execute            automatically set library path, then run a program
#       finish             complete the installation of libtool libraries
#       install            install libraries or executables
#       link               create a library or an executable
#       uninstall          remove libraries from an installed directory
#
# MODE-ARGS vary depending on the MODE.
# Try `$progname --help --mode=MODE' for a more detailed description of MODE.
#
# When reporting a bug, please describe a test case to reproduce it and
# include the following information:
#
#       host-triplet:	$host
#       shell:		$SHELL
#       compiler:		$LTCC
#       compiler flags:		$LTCFLAGS
#       linker:		$LD (gnu? $with_gnu_ld)
#       $progname:		(GNU libtool) 2.2.6b Debian-2.2.6b-2
#       automake:		$automake_version
#       autoconf:		$autoconf_version
#
# Report bugs to <bug-libtool@gnu.org>.

PROGRAM=ltmain.sh
PACKAGE=libtool
VERSION="2.2.6b Debian-2.2.6b-2"
TIMESTAMP=""
package_revision=1.3017

# Be Bourne compatible
if test -n "${ZSH_VERSION+set}" && (emulate sh) >/dev/null 2>&1; then
  emulate sh
  NULLCMD=:
  # Zsh 3.x and 4.x performs word splitting on ${1+"$@"}, which
  # is contrary to our usage.  Disable this feature.
  alias -g '${1+"$@"}'='"$@"'
  setopt NO_GLOB_SUBST
else
  case `(set -o) 2>/dev/null` in *posix*) set -o posix;; esac
fi
BIN_SH=xpg4; export BIN_SH # for Tru64
DUALCASE=1; export DUALCASE # for MKS sh

# NLS nuisances: We save the old values to restore during execute mode.
# Only set LANG and LC_ALL to C if already set.
# These must not be set unconditionally because not all systems understand
# e.g. LANG=C (notably SCO).
lt_user_locale=
lt_safe_locale=
for lt_var in LANG LANGUAGE LC_ALL LC_CTYPE LC_COLLATE LC_MESSAGES
do
  eval "if test \"\${$lt_var+set}\" = set; then
          save_$lt_var=\$$lt_var
          $lt_var=C
	  export $lt_var
	  lt_user_locale=\"$lt_var=\\\$save_\$lt_var; \$lt_user_locale\"
	  lt_safe_locale=\"$lt_var=C; \$lt_safe_locale\"
	fi"
done

$lt_unset CDPATH





: ${CP="cp -f"}
: ${ECHO="echo"}
: ${EGREP="/bin/grep -E"}
: ${FGREP="/bin/grep -F"}
: ${GREP="/bin/grep"}
: ${LN_S="ln -s"}
: ${MAKE="make"}
: ${MKDIR="mkdir"}
: ${MV="mv -f"}
: ${RM="rm -f"}
: ${SED="/bin/sed"}
: ${SHELL="${CONFIG_SHELL-/bin/sh}"}
: ${Xsed="$SED -e 1s/^X//"}

# Global variables:
EXIT_SUCCESS=0
EXIT_FAILURE=1
EXIT_MISMATCH=63  # $? = 63 is used to indicate version mismatch to missing.
EXIT_SKIP=77	  # $? = 77 is used to indicate a skipped test to automake.

exit_status=$EXIT_SUCCESS

# Make sure IFS has a sensible default
lt_nl='
'
IFS=" 	$lt_nl"

dirname="s,/[^/]*$,,"
basename="s,^.*/,,"

# func_dirname_and_basename file append nondir_replacement
# perform func_basename and func_dirname in a single function
# call:
#   dirname:  Compute the dirname of FILE.  If nonempty,
#             add APPEND to the result, otherwise set result
#             to NONDIR_REPLACEMENT.
#             value returned in "$func_dirname_result"
#   basename: Compute filename of FILE.
#             value retuned in "$func_basename_result"
# Implementation must be kept synchronized with func_dirname
# and func_basename. For efficiency, we do not delegate to
# those functions but instead duplicate the functionality here.
func_dirname_and_basename ()
{
  # Extract subdirectory from the argument.
  func_dirname_result=`$ECHO "X${1}" | $Xsed -e "$dirname"`
  if test "X$func_dirname_result" = "X${1}"; then
    func_dirname_result="${3}"
  else
    func_dirname_result="$func_dirname_result${2}"
  fi
  func_basename_result=`$ECHO "X${1}" | $Xsed -e "$basename"`
}

# Generated shell functions inserted here.

# Work around backward compatibility issue on IRIX 6.5. On IRIX 6.4+, sh
# is ksh but when the shell is invoked as "sh" and the current value of
# the _XPG environment variable is not equal to 1 (one), the special
# positional parameter $0, within a function call, is the name of the
# function.
progpath="$0"

# The name of this program:
# In the unlikely event $progname began with a '-', it would play havoc with
# func_echo (imagine progname=-n), so we prepend ./ in that case:
func_dirname_and_basename "$progpath"
progname=$func_basename_result
case $progname in
  -*) progname=./$progname ;;
esac

# Make sure we have an absolute path for reexecution:
case $progpath in
  [\\/]*|[A-Za-z]:\\*) ;;
  *[\\/]*)
     progdir=$func_dirname_result
     progdir=`cd "$progdir" && pwd`
     progpath="$progdir/$progname"
     ;;
  *)
     save_IFS="$IFS"
     IFS=:
     for progdir in $PATH; do
       IFS="$save_IFS"
       test -x "$progdir/$progname" && break
     done
     IFS="$save_IFS"
     test -n "$progdir" || progdir=`pwd`
     progpath="$progdir/$progname"
     ;;
esac

# Sed substitution that helps us do robust quoting.  It backslashifies
# metacharacters that are still active within double-quoted strings.
Xsed="${SED}"' -e 1s/^X//'
sed_quote_subst='s/\([`"$\\]\)/\\\1/g'

# Same as above, but do not quote variable references.
double_quote_subst='s/\(["`\\]\)/\\\1/g'

# Re-`\' parameter expansions in output of double_quote_subst that were
# `\'-ed in input to the same.  If an odd number of `\' preceded a '$'
# in input to double_quote_subst, that '$' was protected from expansion.
# Since each input `\' is now two `\'s, look for any number of runs of
# four `\'s followed by two `\'s and then a '$'.  `\' that '$'.
bs='\\'
bs2='\\\\'
bs4='\\\\\\\\'
dollar='\$'
sed_double_backslash="\
  s/$bs4/&\\
/g
  s/^$bs2$dollar/$bs&/
  s/\\([^$bs]\\)$bs2$dollar/\\1$bs2$bs$dollar/g
  s/\n//g"

# Standard options:
opt_dry_run=false
opt_help=false
opt_quiet=false
opt_verbose=false
opt_warning=:

# func_echo arg...
# Echo program name prefixed message, along with the current mode
# name if it has been set yet.
func_echo ()
{
    $ECHO "$progname${mode+: }$mode: $*"
}

# func_verbose arg...
# Echo program name prefixed message in verbose mode only.
func_verbose ()
{
    $opt_verbose && func_echo ${1+"$@"}

    # A bug in bash halts the script if the last line of a function
    # fails when set -e is in force, so we need another command to
    # work around that:
    :
}

# func_error arg...
# Echo program name prefixed message to standard error.
func_error ()
{
    $ECHO "$progname${mode+: }$mode: "${1+"$@"} 1>&2
}

# func_warning arg...
# Echo program name prefixed warning message to standard error.
func_warning ()
{
    $opt_warning && $ECHO "$progname${mode+: }$mode: warning: "${1+"$@"} 1>&2

    # bash bug again:
    :
}

# func_fatal_error arg...
# Echo program name prefixed message to standard error, and exit.
func_fatal_error ()
{
    func_error ${1+"$@"}
    exit $EXIT_FAILURE
}

# func_fatal_help arg...
# Echo program name prefixed message to standard error, followed by
# a help hint, and exit.
func_fatal_help ()
{
    func_error ${1+"$@"}
    func_fatal_error "$help"
}
help="Try \`$progname --help' for more information."  ## default


# func_grep expression filename
# Check whether EXPRESSION matches any line of FILENAME, without output.
func_grep ()
{
    $GREP "$1" "$2" >/dev/null 2>&1
}


# func_mkdir_p directory-path
# Make sure the entire path to DIRECTORY-PATH is available.
func_mkdir_p ()
{
    my_directory_path="$1"
    my_dir_list=

    if test -n "$my_directory_path" && test "$opt_dry_run" != ":"; then

      # Protect directory names starting with `-'
      case $my_directory_path in
        -*) my_directory_path="./$my_directory_path" ;;
      esac

      # While some portion of DIR does not yet exist...
      while test ! -d "$my_directory_path"; do
        # ...make a list in topmost first order.  Use a colon delimited
	# list incase some portion of path contains whitespace.
        my_dir_list="$my_directory_path:$my_dir_list"

        # If the last portion added has no slash in it, the list is done
        case $my_directory_path in */*) ;; *) break ;; esac

        # ...otherwise throw away the child directory and loop
        my_directory_path=`$ECHO "X$my_directory_path" | $Xsed -e "$dirname"`
      done
      my_dir_list=`$ECHO "X$my_dir_list" | $Xsed -e 's,:*$,,'`

      save_mkdir_p_IFS="$IFS"; IFS=':'
      for my_dir in $my_dir_list; do
	IFS="$save_mkdir_p_IFS"
        # mkdir can fail with a `File exist' error if two processes
        # try to create one of the directories concurrently.  Don't
        # stop in that case!
        $MKDIR "$my_dir" 2>/dev/null || :
      done
      IFS="$save_mkdir_p_IFS"

      # Bail out if we (or some other process) failed to create a directory.
      test -d "$my_directory_path" || \
        func_fatal_error "Failed to create \`$1'"
    fi
}


# func_mktempdir [string]
# Make a temporary directory that won't clash with other running
# libtool processes, and avoids race conditions if possible.  If
# given, STRING is the basename for that directory.
func_mktempdir ()
{
    my_template="${TMPDIR-/tmp}/${1-$progname}"

    if test "$opt_dry_run" = ":"; then
      # Return a directory name, but don't create it in dry-run mode
      my_tmpdir="${my_template}-$$"
    else

      # If mktemp works, use that first and foremost
      my_tmpdir=`mktemp -d "${my_template}-XXXXXXXX" 2>/dev/null`

      if test ! -d "$my_tmpdir"; then
        # Failing that, at least try and use $RANDOM to avoid a race
        my_tmpdir="${my_template}-${RANDOM-0}$$"

        save_mktempdir_umask=`umask`
        umask 0077
        $MKDIR "$my_tmpdir"
        umask $save_mktempdir_umask
      fi

      # If we're not in dry-run mode, bomb out on failure
      test -d "$my_tmpdir" || \
        func_fatal_error "cannot create temporary directory \`$my_tmpdir'"
    fi

    $ECHO "X$my_tmpdir" | $Xsed
}


# func_quote_for_eval arg
# Aesthetically quote ARG to be evaled later.
# This function returns two values: FUNC_QUOTE_FOR_EVAL_RESULT
# is double-quoted, suitable for a subsequent eval, whereas
# FUNC_QUOTE_FOR_EVAL_UNQUOTED_RESULT has merely all characters
# which are still active within double quotes backslashified.
func_quote_for_eval ()
{
    case $1 in
      *[\\\`\"\$]*)
	func_quote_for_eval_unquoted_result=`$ECHO "X$1" | $Xsed -e "$sed_quote_subst"` ;;
      *)
        func_quote_for_eval_unquoted_result="$1" ;;
    esac

    case $func_quote_for_eval_unquoted_result in
      # Double-quote args containing shell metacharacters to delay
      # word splitting, command substitution and and variable
      # expansion for a subsequent eval.
      # Many Bourne shells cannot handle close brackets correctly
      # in scan sets, so we specify it separately.
      *[\[\~\#\^\&\*\(\)\{\}\|\;\<\>\?\'\ \	]*|*]*|"")
        func_quote_for_eval_result="\"$func_quote_for_eval_unquoted_result\""
        ;;
      *)
        func_quote_for_eval_result="$func_quote_for_eval_unquoted_result"
    esac
}


# func_quote_for_expand arg
# Aesthetically quote ARG to be evaled later; same as above,
# but do not quote variable references.
func_quote_for_expand ()
{
    case $1 in
      *[\\\`\"]*)
	my_arg=`$ECHO "X$1" | $Xsed \
	    -e "$double_quote_subst" -e "$sed_double_backslash"` ;;
      *)
        my_arg="$1" ;;
    esac

    case $my_arg in
      # Double-quote args containing shell metacharacters to delay
      # word splitting and command substitution for a subsequent eval.
      # Many Bourne shells cannot handle close brackets correctly
      # in scan sets, so we specify it separately.
      *[\[\~\#\^\&\*\(\)\{\}\|\;\<\>\?\'\ \	]*|*]*|"")
        my_arg="\"$my_arg\""
        ;;
    esac

    func_quote_for_expand_result="$my_arg"
}


# func_show_eval cmd [fail_exp]
# Unless opt_silent is true, then output CMD.  Then, if opt_dryrun is
# not true, evaluate CMD.  If the evaluation of CMD fails, and FAIL_EXP
# is given, then evaluate it.
func_show_eval ()
{
    my_cmd="$1"
    my_fail_exp="${2-:}"

    ${opt_silent-false} || {
      func_quote_for_expand "$my_cmd"
      eval "func_echo $func_quote_for_expand_result"
    }

    if ${opt_dry_run-false}; then :; else
      eval "$my_cmd"
      my_status=$?
      if test "$my_status" -eq 0; then :; else
	eval "(exit $my_status); $my_fail_exp"
      fi
    fi
}


# func_show_eval_locale cmd [fail_exp]
# Unless opt_silent is true, then output CMD.  Then, if opt_dryrun is
# not true, evaluate CMD.  If the evaluation of CMD fails, and FAIL_EXP
# is given, then evaluate it.  Use the saved locale for evaluation.
func_show_eval_locale ()
{
    my_cmd="$1"
    my_fail_exp="${2-:}"

    ${opt_silent-false} || {
      func_quote_for_expand "$my_cmd"
      eval "func_echo $func_quote_for_expand_result"
    }

    if ${opt_dry_run-false}; then :; else
      eval "$lt_user_locale
	    $my_cmd"
      my_status=$?
      eval "$lt_safe_locale"
      if test "$my_status" -eq 0; then :; else
	eval "(exit $my_status); $my_fail_exp"
      fi
    fi
}





# func_version
# Echo version message to standard output and exit.
func_version ()
{
    $SED -n '/^# '$PROGRAM' (GNU /,/# warranty; / {
        s/^# //
	s/^# *$//
        s/\((C)\)[ 0-9,-]*\( [1-9][0-9]*\)/\1\2/
        p
     }' < "$progpath"
     exit $?
}

# func_usage
# Echo short help message to standard output and exit.
func_usage ()
{
    $SED -n '/^# Usage:/,/# -h/ {
        s/^# //
	s/^# *$//
	s/\$progname/'$progname'/
	p
    }' < "$progpath"
    $ECHO
    $ECHO "run \`$progname --help | more' for full usage"
    exit $?
}

# func_help
# Echo long help message to standard output and exit.
func_help ()
{
    $SED -n '/^# Usage:/,/# Report bugs to/ {
        s/^# //
	s/^# *$//
	s*\$progname*'$progname'*
	s*\$host*'"$host"'*
	s*\$SHELL*'"$SHELL"'*
	s*\$LTCC*'"$LTCC"'*
	s*\$LTCFLAGS*'"$LTCFLAGS"'*
	s*\$LD*'"$LD"'*
	s/\$with_gnu_ld/'"$with_gnu_ld"'/
	s/\$automake_version/'"`(automake --version) 2>/dev/null |$SED 1q`"'/
	s/\$autoconf_version/'"`(autoconf --version) 2>/dev/null |$SED 1q`"'/
	p
     }' < "$progpath"
    exit $?
}

# func_missing_arg argname
# Echo program name prefixed message to standard error and set global
# exit_cmd.
func_missing_arg ()
{
    func_error "missing argument for $1"
    exit_cmd=exit
}

exit_cmd=:





# Check that we have a working $ECHO.
if test "X$1" = X--no-reexec; then
  # Discard the --no-reexec flag, and continue.
  shift
elif test "X$1" = X--fallback-echo; then
  # Avoid inline document here, it may be left over
  :
elif test "X`{ $ECHO '\t'; } 2>/dev/null`" = 'X\t'; then
  # Yippee, $ECHO works!
  :
else
  # Restart under the correct shell, and then maybe $ECHO will work.
  exec $SHELL "$progpath" --no-reexec ${1+"$@"}
fi

if test "X$1" = X--fallback-echo; then
  # used as fallback echo
  shift
  cat <<EOF
$*
EOF
  exit $EXIT_SUCCESS
fi

magic="%%%MAGIC variable%%%"
magic_exe="%%%MAGIC EXE variable%%%"

# Global variables.
# $mode is unset
nonopt=
execute_dlfiles=
preserve_args=
lo2o="s/\\.lo\$/.${objext}/"
o2lo="s/\\.${objext}\$/.lo/"
extracted_archives=
extracted_serial=0

opt_dry_run=false
opt_duplicate_deps=false
opt_silent=false
opt_debug=:

# If this variable is set in any of the actions, the command in it
# will be execed at the end.  This prevents here-documents from being
# left over by shells.
exec_cmd=

# func_fatal_configuration arg...
# Echo program name prefixed message to standard error, followed by
# a configuration failure hint, and exit.
func_fatal_configuration ()
{
    func_error ${1+"$@"}
    func_error "See the $PACKAGE documentation for more information."
    func_fatal_error "Fatal configuration error."
}


# func_config
# Display the configuration for all the tags in this script.
func_config ()
{
    re_begincf='^# ### BEGIN LIBTOOL'
    re_endcf='^# ### END LIBTOOL'

    # Default configuration.
    $SED "1,/$re_begincf CONFIG/d;/$re_endcf CONFIG/,\$d" < "$progpath"

    # Now print the configurations for the tags.
    for tagname in $taglist; do
      $SED -n "/$re_begincf TAG CONFIG: $tagname\$/,/$re_endcf TAG CONFIG: $tagname\$/p" < "$progpath"
    done

    exit $?
}

# func_features
# Display the features supported by this script.
func_features ()
{
    $ECHO "host: $host"
    if test "$build_libtool_libs" = yes; then
      $ECHO "enable shared libraries"
    else
      $ECHO "disable shared libraries"
    fi
    if test "$build_old_libs" = yes; then
      $ECHO "enable static libraries"
    else
      $ECHO "disable static libraries"
    fi

    exit $?
}

# func_enable_tag tagname
# Verify that TAGNAME is valid, and either flag an error and exit, or
# enable the TAGNAME tag.  We also add TAGNAME to the global $taglist
# variable here.
func_enable_tag ()
{
  # Global variable:
  tagname="$1"

  re_begincf="^# ### BEGIN LIBTOOL TAG CONFIG: $tagname\$"
  re_endcf="^# ### END LIBTOOL TAG CONFIG: $tagname\$"
  sed_extractcf="/$re_begincf/,/$re_endcf/p"

  # Validate tagname.
  case $tagname in
    *[!-_A-Za-z0-9,/]*)
      func_fatal_error "invalid tag name: $tagname"
      ;;
  esac

  # Don't test for the "default" C tag, as we know it's
  # there but not specially marked.
  case $tagname in
    CC) ;;
    *)
      if $GREP "$re_begincf" "$progpath" >/dev/null 2>&1; then
	taglist="$taglist $tagname"

	# Evaluate the configuration.  Be careful to quote the path
	# and the sed script, to avoid splitting on whitespace, but
	# also don't use non-portable quotes within backquotes within
	# quotes we have to do it in 2 steps:
	extractedcf=`$SED -n -e "$sed_extractcf" < "$progpath"`
	eval "$extractedcf"
      else
	func_error "ignoring unknown tag $tagname"
      fi
      ;;
  esac
}

# Parse options once, thoroughly.  This comes as soon as possible in
# the script to make things like `libtool --version' happen quickly.
{

  # Shorthand for --mode=foo, only valid as the first argument
  case $1 in
  clean|clea|cle|cl)
    shift; set dummy --mode clean ${1+"$@"}; shift
    ;;
  compile|compil|compi|comp|com|co|c)
    shift; set dummy --mode compile ${1+"$@"}; shift
    ;;
  execute|execut|execu|exec|exe|ex|e)
    shift; set dummy --mode execute ${1+"$@"}; shift
    ;;
  finish|finis|fini|fin|fi|f)
    shift; set dummy --mode finish ${1+"$@"}; shift
    ;;
  install|instal|insta|inst|ins|in|i)
    shift; set dummy --mode install ${1+"$@"}; shift
    ;;
  link|lin|li|l)
    shift; set dummy --mode link ${1+"$@"}; shift
    ;;
  uninstall|uninstal|uninsta|uninst|unins|unin|uni|un|u)
    shift; set dummy --mode uninstall ${1+"$@"}; shift
    ;;
  esac

  # Parse non-mode specific arguments:
  while test "$#" -gt 0; do
    opt="$1"
    shift

    case $opt in
      --config)		func_config					;;

      --debug)		preserve_args="$preserve_args $opt"
			func_echo "enabling shell trace mode"
			opt_debug='set -x'
			$opt_debug
			;;

      -dlopen)		test "$#" -eq 0 && func_missing_arg "$opt" && break
			execute_dlfiles="$execute_dlfiles $1"
			shift
			;;

      --dry-run | -n)	opt_dry_run=:					;;
      --features)       func_features					;;
      --finish)		mode="finish"					;;

      --mode)		test "$#" -eq 0 && func_missing_arg "$opt" && break
			case $1 in
			  # Valid mode arguments:
			  clean)	;;
			  compile)	;;
			  execute)	;;
			  finish)	;;
			  install)	;;
			  link)		;;
			  relink)	;;
			  uninstall)	;;

			  # Catch anything else as an error
			  *) func_error "invalid argument for $opt"
			     exit_cmd=exit
			     break
			     ;;
		        esac

			mode="$1"
			shift
			;;

      --preserve-dup-deps)
			opt_duplicate_deps=:				;;

      --quiet|--silent)	preserve_args="$preserve_args $opt"
			opt_silent=:
			;;

      --verbose| -v)	preserve_args="$preserve_args $opt"
			opt_silent=false
			;;

      --tag)		test "$#" -eq 0 && func_missing_arg "$opt" && break
			preserve_args="$preserve_args $opt $1"
			func_enable_tag "$1"	# tagname is set here
			shift
			;;

      # Separate optargs to long options:
      -dlopen=*|--mode=*|--tag=*)
			func_opt_split "$opt"
			set dummy "$func_opt_split_opt" "$func_opt_split_arg" ${1+"$@"}
			shift
			;;

      -\?|-h)		func_usage					;;
      --help)		opt_help=:					;;
      --version)	func_version					;;

      -*)		func_fatal_help "unrecognized option \`$opt'"	;;

      *)		nonopt="$opt"
			break
			;;
    esac
  done


  case $host in
    *cygwin* | *mingw* | *pw32* | *cegcc*)
      # don't eliminate duplications in $postdeps and $predeps
      opt_duplicate_compiler_generated_deps=:
      ;;
    *)
      opt_duplicate_compiler_generated_deps=$opt_duplicate_deps
      ;;
  esac

  # Having warned about all mis-specified options, bail out if
  # anything was wrong.
  $exit_cmd $EXIT_FAILURE
}

# func_check_version_match
# Ensure that we are using m4 macros, and libtool script from the same
# release of libtool.
func_check_version_match ()
{
  if test "$package_revision" != "$macro_revision"; then
    if test "$VERSION" != "$macro_version"; then
      if test -z "$macro_version"; then
        cat >&2 <<_LT_EOF
$progname: Version mismatch error.  This is $PACKAGE $VERSION, but the
$progname: definition of this LT_INIT comes from an older release.
$progname: You should recreate aclocal.m4 with macros from $PACKAGE $VERSION
$progname: and run autoconf again.
_LT_EOF
      else
        cat >&2 <<_LT_EOF
$progname: Version mismatch error.  This is $PACKAGE $VERSION, but the
$progname: definition of this LT_INIT comes from $PACKAGE $macro_version.
$progname: You should recreate aclocal.m4 with macros from $PACKAGE $VERSION
$progname: and run autoconf again.
_LT_EOF
      fi
    else
      cat >&2 <<_LT_EOF
$progname: Version mismatch error.  This is $PACKAGE $VERSION, revision $package_revision,
$progname: but the definition of this LT_INIT comes from revision $macro_revision.
$progname: You should recreate aclocal.m4 with macros from revision $package_revision
$progname: of $PACKAGE $VERSION and run autoconf again.
_LT_EOF
    fi

    exit $EXIT_MISMATCH
  fi
}


## ----------- ##
##    Main.    ##
## ----------- ##

$opt_help || {
  # Sanity checks first:
  func_check_version_match

  if test "$build_libtool_libs" != yes && test "$build_old_libs" != yes; then
    func_fatal_configuration "not configured to build any kind of library"
  fi

  test -z "$mode" && func_fatal_error "error: you must specify a MODE."


  # Darwin sucks
  eval std_shrext=\"$shrext_cmds\"


  # Only execute mode is allowed to have -dlopen flags.
  if test -n "$execute_dlfiles" && test "$mode" != execute; then
    func_error "unrecognized option \`-dlopen'"
    $ECHO "$help" 1>&2
    exit $EXIT_FAILURE
  fi

  # Change the help message to a mode-specific one.
  generic_help="$help"
  help="Try \`$progname --help --mode=$mode' for more information."
}


# func_lalib_p file
# True iff FILE is a libtool `.la' library or `.lo' object file.
# This function is only a basic sanity check; it will hardly flush out
# determined imposters.
func_lalib_p ()
{
    test -f "$1" &&
      $SED -e 4q "$1" 2>/dev/null \
        | $GREP "^# Generated by .*$PACKAGE" > /dev/null 2>&1
}

# func_lalib_unsafe_p file
# True iff FILE is a libtool `.la' library or `.lo' object file.
# This function implements the same check as func_lalib_p without
# resorting to external programs.  To this end, it redirects stdin and
# closes it afterwards, without saving the original file descriptor.
# As a safety measure, use it only where a negative result would be
# fatal anyway.  Works if `file' does not exist.
func_lalib_unsafe_p ()
{
    lalib_p=no
    if test -f "$1" && test -r "$1" && exec 5<&0 <"$1"; then
	for lalib_p_l in 1 2 3 4
	do
	    read lalib_p_line
	    case "$lalib_p_line" in
		\#\ Generated\ by\ *$PACKAGE* ) lalib_p=yes; break;;
	    esac
	done
	exec 0<&5 5<&-
    fi
    test "$lalib_p" = yes
}

# func_ltwrapper_script_p file
# True iff FILE is a libtool wrapper script
# This function is only a basic sanity check; it will hardly flush out
# determined imposters.
func_ltwrapper_script_p ()
{
    func_lalib_p "$1"
}

# func_ltwrapper_executable_p file
# True iff FILE is a libtool wrapper executable
# This function is only a basic sanity check; it will hardly flush out
# determined imposters.
func_ltwrapper_executable_p ()
{
    func_ltwrapper_exec_suffix=
    case $1 in
    *.exe) ;;
    *) func_ltwrapper_exec_suffix=.exe ;;
    esac
    $GREP "$magic_exe" "$1$func_ltwrapper_exec_suffix" >/dev/null 2>&1
}

# func_ltwrapper_scriptname file
# Assumes file is an ltwrapper_executable
# uses $file to determine the appropriate filename for a
# temporary ltwrapper_script.
func_ltwrapper_scriptname ()
{
    func_ltwrapper_scriptname_result=""
    if func_ltwrapper_executable_p "$1"; then
	func_dirname_and_basename "$1" "" "."
	func_stripname '' '.exe' "$func_basename_result"
	func_ltwrapper_scriptname_result="$func_dirname_result/$objdir/${func_stripname_result}_ltshwrapper"
    fi
}

# func_ltwrapper_p file
# True iff FILE is a libtool wrapper script or wrapper executable
# This function is only a basic sanity check; it will hardly flush out
# determined imposters.
func_ltwrapper_p ()
{
    func_ltwrapper_script_p "$1" || func_ltwrapper_executable_p "$1"
}


# func_execute_cmds commands fail_cmd
# Execute tilde-delimited COMMANDS.
# If FAIL_CMD is given, eval that upon failure.
# FAIL_CMD may read-access the current command in variable CMD!
func_execute_cmds ()
{
    $opt_debug
    save_ifs=$IFS; IFS='~'
    for cmd in $1; do
      IFS=$save_ifs
      eval cmd=\"$cmd\"
      func_show_eval "$cmd" "${2-:}"
    done
    IFS=$save_ifs
}


# func_source file
# Source FILE, adding directory component if necessary.
# Note that it is not necessary on cygwin/mingw to append a dot to
# FILE even if both FILE and FILE.exe exist: automatic-append-.exe
# behavior happens only for exec(3), not for open(2)!  Also, sourcing
# `FILE.' does not work on cygwin managed mounts.
func_source ()
{
    $opt_debug
    case $1 in
    */* | *\\*)	. "$1" ;;
    *)		. "./$1" ;;
    esac
}


# func_infer_tag arg
# Infer tagged configuration to use if any are available and
# if one wasn't chosen via the "--tag" command line option.
# Only attempt this if the compiler in the base compile
# command doesn't match the default compiler.
# arg is usually of the form 'gcc ...'
func_infer_tag ()
{
    $opt_debug
    if test -n "$available_tags" && test -z "$tagname"; then
      CC_quoted=
      for arg in $CC; do
        func_quote_for_eval "$arg"
	CC_quoted="$CC_quoted $func_quote_for_eval_result"
      done
      case $@ in
      # Blanks in the command may have been stripped by the calling shell,
      # but not from the CC environment variable when configure was run.
      " $CC "* | "$CC "* | " `$ECHO $CC` "* | "`$ECHO $CC` "* | " $CC_quoted"* | "$CC_quoted "* | " `$ECHO $CC_quoted` "* | "`$ECHO $CC_quoted` "*) ;;
      # Blanks at the start of $base_compile will cause this to fail
      # if we don't check for them as well.
      *)
	for z in $available_tags; do
	  if $GREP "^# ### BEGIN LIBTOOL TAG CONFIG: $z$" < "$progpath" > /dev/null; then
	    # Evaluate the configuration.
	    eval "`${SED} -n -e '/^# ### BEGIN LIBTOOL TAG CONFIG: '$z'$/,/^# ### END LIBTOOL TAG CONFIG: '$z'$/p' < $progpath`"
	    CC_quoted=
	    for arg in $CC; do
	      # Double-quote args containing other shell metacharacters.
	      func_quote_for_eval "$arg"
	      CC_quoted="$CC_quoted $func_quote_for_eval_result"
	    done
	    case "$@ " in
	      " $CC "* | "$CC "* | " `$ECHO $CC` "* | "`$ECHO $CC` "* | " $CC_quoted"* | "$CC_quoted "* | " `$ECHO $CC_quoted` "* | "`$ECHO $CC_quoted` "*)
	      # The compiler in the base compile command matches
	      # the one in the tagged configuration.
	      # Assume this is the tagged configuration we want.
	      tagname=$z
	      break
	      ;;
	    esac
	  fi
	done
	# If $tagname still isn't set, then no tagged configuration
	# was found and let the user know that the "--tag" command
	# line option must be used.
	if test -z "$tagname"; then
	  func_echo "unable to infer tagged configuration"
	  func_fatal_error "specify a tag with \`--tag'"
#	else
#	  func_verbose "using $tagname tagged configuration"
	fi
	;;
      esac
    fi
}



# func_write_libtool_object output_name pic_name nonpic_name
# Create a libtool object file (analogous to a ".la" file),
# but don't create it if we're doing a dry run.
func_write_libtool_object ()
{
    write_libobj=${1}
    if test "$build_libtool_libs" = yes; then
      write_lobj=\'${2}\'
    else
      write_lobj=none
    fi

    if test "$build_old_libs" = yes; then
      write_oldobj=\'${3}\'
    else
      write_oldobj=none
    fi

    $opt_dry_run || {
      cat >${write_libobj}T <<EOF
# $write_libobj - a libtool object file
# Generated by $PROGRAM (GNU $PACKAGE$TIMESTAMP) $VERSION
#
# Please DO NOT delete this file!
# It is necessary for linking the library.

# Name of the PIC object.
pic_object=$write_lobj

# Name of the non-PIC object
non_pic_object=$write_oldobj

EOF
      $MV "${write_libobj}T" "${write_libobj}"
    }
}

# func_mode_compile arg...
func_mode_compile ()
{
    $opt_debug
    # Get the compilation command and the source file.
    base_compile=
    srcfile="$nonopt"  #  always keep a non-empty value in "srcfile"
    suppress_opt=yes
    suppress_output=
    arg_mode=normal
    libobj=
    later=
    pie_flag=

    for arg
    do
      case $arg_mode in
      arg  )
	# do not "continue".  Instead, add this to base_compile
	lastarg="$arg"
	arg_mode=normal
	;;

      target )
	libobj="$arg"
	arg_mode=normal
	continue
	;;

      normal )
	# Accept any command-line options.
	case $arg in
	-o)
	  test -n "$libobj" && \
	    func_fatal_error "you cannot specify \`-o' more than once"
	  arg_mode=target
	  continue
	  ;;

	-pie | -fpie | -fPIE)
          pie_flag="$pie_flag $arg"
	  continue
	  ;;

	-shared | -static | -prefer-pic | -prefer-non-pic)
	  later="$later $arg"
	  continue
	  ;;

	-no-suppress)
	  suppress_opt=no
	  continue
	  ;;

	-Xcompiler)
	  arg_mode=arg  #  the next one goes into the "base_compile" arg list
	  continue      #  The current "srcfile" will either be retained or
	  ;;            #  replaced later.  I would guess that would be a bug.

	-Wc,*)
	  func_stripname '-Wc,' '' "$arg"
	  args=$func_stripname_result
	  lastarg=
	  save_ifs="$IFS"; IFS=','
	  for arg in $args; do
	    IFS="$save_ifs"
	    func_quote_for_eval "$arg"
	    lastarg="$lastarg $func_quote_for_eval_result"
	  done
	  IFS="$save_ifs"
	  func_stripname ' ' '' "$lastarg"
	  lastarg=$func_stripname_result

	  # Add the arguments to base_compile.
	  base_compile="$base_compile $lastarg"
	  continue
	  ;;

	*)
	  # Accept the current argument as the source file.
	  # The previous "srcfile" becomes the current argument.
	  #
	  lastarg="$srcfile"
	  srcfile="$arg"
	  ;;
	esac  #  case $arg
	;;
      esac    #  case $arg_mode

      # Aesthetically quote the previous argument.
      func_quote_for_eval "$lastarg"
      base_compile="$base_compile $func_quote_for_eval_result"
    done # for arg

    case $arg_mode in
    arg)
      func_fatal_error "you must specify an argument for -Xcompile"
      ;;
    target)
      func_fatal_error "you must specify a target with \`-o'"
      ;;
    *)
      # Get the name of the library object.
      test -z "$libobj" && {
	func_basename "$srcfile"
	libobj="$func_basename_result"
      }
      ;;
    esac

    # Recognize several different file suffixes.
    # If the user specifies -o file.o, it is replaced with file.lo
    case $libobj in
    *.[cCFSifmso] | \
    *.ada | *.adb | *.ads | *.asm | \
    *.c++ | *.cc | *.ii | *.class | *.cpp | *.cxx | \
    *.[fF][09]? | *.for | *.java | *.obj | *.sx)
      func_xform "$libobj"
      libobj=$func_xform_result
      ;;
    esac

    case $libobj in
    *.lo) func_lo2o "$libobj"; obj=$func_lo2o_result ;;
    *)
      func_fatal_error "cannot determine name of library object from \`$libobj'"
      ;;
    esac

    func_infer_tag $base_compile

    for arg in $later; do
      case $arg in
      -shared)
	test "$build_libtool_libs" != yes && \
	  func_fatal_configuration "can not build a shared library"
	build_old_libs=no
	continue
	;;

      -static)
	build_libtool_libs=no
	build_old_libs=yes
	continue
	;;

      -prefer-pic)
	pic_mode=yes
	continue
	;;

      -prefer-non-pic)
	pic_mode=no
	continue
	;;
      esac
    done

    func_quote_for_eval "$libobj"
    test "X$libobj" != "X$func_quote_for_eval_result" \
      && $ECHO "X$libobj" | $GREP '[]~#^*{};<>?"'"'"'	 &()|`$[]' \
      && func_warning "libobj name \`$libobj' may not contain shell special characters."
    func_dirname_and_basename "$obj" "/" ""
    objname="$func_basename_result"
    xdir="$func_dirname_result"
    lobj=${xdir}$objdir/$objname

    test -z "$base_compile" && \
      func_fatal_help "you must specify a compilation command"

    # Delete any leftover library objects.
    if test "$build_old_libs" = yes; then
      removelist="$obj $lobj $libobj ${libobj}T"
    else
      removelist="$lobj $libobj ${libobj}T"
    fi

    # On Cygwin there's no "real" PIC flag so we must build both object types
    case $host_os in
    cygwin* | mingw* | pw32* | os2* | cegcc*)
      pic_mode=default
      ;;
    esac
    if test "$pic_mode" = no && test "$deplibs_check_method" != pass_all; then
      # non-PIC code in shared libraries is not supported
      pic_mode=default
    fi

    # Calculate the filename of the output object if compiler does
    # not support -o with -c
    if test "$compiler_c_o" = no; then
      output_obj=`$ECHO "X$srcfile" | $Xsed -e 's%^.*/%%' -e 's%\.[^.]*$%%'`.${objext}
      lockfile="$output_obj.lock"
    else
      output_obj=
      need_locks=no
      lockfile=
    fi

    # Lock this critical section if it is needed
    # We use this script file to make the link, it avoids creating a new file
    if test "$need_locks" = yes; then
      until $opt_dry_run || ln "$progpath" "$lockfile" 2>/dev/null; do
	func_echo "Waiting for $lockfile to be removed"
	sleep 2
      done
    elif test "$need_locks" = warn; then
      if test -f "$lockfile"; then
	$ECHO "\
*** ERROR, $lockfile exists and contains:
`cat $lockfile 2>/dev/null`

This indicates that another process is trying to use the same
temporary object file, and libtool could not work around it because
your compiler does not support \`-c' and \`-o' together.  If you
repeat this compilation, it may succeed, by chance, but you had better
avoid parallel builds (make -j) in this platform, or get a better
compiler."

	$opt_dry_run || $RM $removelist
	exit $EXIT_FAILURE
      fi
      removelist="$removelist $output_obj"
      $ECHO "$srcfile" > "$lockfile"
    fi

    $opt_dry_run || $RM $removelist
    removelist="$removelist $lockfile"
    trap '$opt_dry_run || $RM $removelist; exit $EXIT_FAILURE' 1 2 15

    if test -n "$fix_srcfile_path"; then
      eval srcfile=\"$fix_srcfile_path\"
    fi
    func_quote_for_eval "$srcfile"
    qsrcfile=$func_quote_for_eval_result

    # Only build a PIC object if we are building libtool libraries.
    if test "$build_libtool_libs" = yes; then
      # Without this assignment, base_compile gets emptied.
      fbsd_hideous_sh_bug=$base_compile

      if test "$pic_mode" != no; then
	command="$base_compile $qsrcfile $pic_flag"
      else
	# Don't build PIC code
	command="$base_compile $qsrcfile"
      fi

      func_mkdir_p "$xdir$objdir"

      if test -z "$output_obj"; then
	# Place PIC objects in $objdir
	command="$command -o $lobj"
      fi

      func_show_eval_locale "$command"	\
          'test -n "$output_obj" && $RM $removelist; exit $EXIT_FAILURE'

      if test "$need_locks" = warn &&
	 test "X`cat $lockfile 2>/dev/null`" != "X$srcfile"; then
	$ECHO "\
*** ERROR, $lockfile contains:
`cat $lockfile 2>/dev/null`

but it should contain:
$srcfile

This indicates that another process is trying to use the same
temporary object file, and libtool could not work around it because
your compiler does not support \`-c' and \`-o' together.  If you
repeat this compilation, it may succeed, by chance, but you had better
avoid parallel builds (make -j) in this platform, or get a better
compiler."

	$opt_dry_run || $RM $removelist
	exit $EXIT_FAILURE
      fi

      # Just move the object if needed, then go on to compile the next one
      if test -n "$output_obj" && test "X$output_obj" != "X$lobj"; then
	func_show_eval '$MV "$output_obj" "$lobj"' \
	  'error=$?; $opt_dry_run || $RM $removelist; exit $error'
      fi

      # Allow error messages only from the first compilation.
      if test "$suppress_opt" = yes; then
	suppress_output=' >/dev/null 2>&1'
      fi
    fi

    # Only build a position-dependent object if we build old libraries.
    if test "$build_old_libs" = yes; then
      if test "$pic_mode" != yes; then
	# Don't build PIC code
	command="$base_compile $qsrcfile$pie_flag"
      else
	command="$base_compile $qsrcfile $pic_flag"
      fi
      if test "$compiler_c_o" = yes; then
	command="$command -o $obj"
      fi

      # Suppress compiler output if we already did a PIC compilation.
      command="$command$suppress_output"
      func_show_eval_locale "$command" \
        '$opt_dry_run || $RM $removelist; exit $EXIT_FAILURE'

      if test "$need_locks" = warn &&
	 test "X`cat $lockfile 2>/dev/null`" != "X$srcfile"; then
	$ECHO "\
*** ERROR, $lockfile contains:
`cat $lockfile 2>/dev/null`

but it should contain:
$srcfile

This indicates that another process is trying to use the same
temporary object file, and libtool could not work around it because
your compiler does not support \`-c' and \`-o' together.  If you
repeat this compilation, it may succeed, by chance, but you had better
avoid parallel builds (make -j) in this platform, or get a better
compiler."

	$opt_dry_run || $RM $removelist
	exit $EXIT_FAILURE
      fi

      # Just move the object if needed
      if test -n "$output_obj" && test "X$output_obj" != "X$obj"; then
	func_show_eval '$MV "$output_obj" "$obj"' \
	  'error=$?; $opt_dry_run || $RM $removelist; exit $error'
      fi
    fi

    $opt_dry_run || {
      func_write_libtool_object "$libobj" "$objdir/$objname" "$objname"

      # Unlock the critical section if it was locked
      if test "$need_locks" != no; then
	removelist=$lockfile
        $RM "$lockfile"
      fi
    }

    exit $EXIT_SUCCESS
}

$opt_help || {
test "$mode" = compile && func_mode_compile ${1+"$@"}
}

func_mode_help ()
{
    # We need to display help for each of the modes.
    case $mode in
      "")
        # Generic help is extracted from the usage comments
        # at the start of this file.
        func_help
        ;;

      clean)
        $ECHO \
"Usage: $progname [OPTION]... --mode=clean RM [RM-OPTION]... FILE...

Remove files from the build directory.

RM is the name of the program to use to delete files associated with each FILE
(typically \`/bin/rm').  RM-OPTIONS are options (such as \`-f') to be passed
to RM.

If FILE is a libtool library, object or program, all the files associated
with it are deleted. Otherwise, only FILE itself is deleted using RM."
        ;;

      compile)
      $ECHO \
"Usage: $progname [OPTION]... --mode=compile COMPILE-COMMAND... SOURCEFILE

Compile a source file into a libtool library object.

This mode accepts the following additional options:

  -o OUTPUT-FILE    set the output file name to OUTPUT-FILE
  -no-suppress      do not suppress compiler output for multiple passes
  -prefer-pic       try to building PIC objects only
  -prefer-non-pic   try to building non-PIC objects only
  -shared           do not build a \`.o' file suitable for static linking
  -static           only build a \`.o' file suitable for static linking

COMPILE-COMMAND is a command to be used in creating a \`standard' object file
from the given SOURCEFILE.

The output file name is determined by removing the directory component from
SOURCEFILE, then substituting the C source code suffix \`.c' with the
library object suffix, \`.lo'."
        ;;

      execute)
        $ECHO \
"Usage: $progname [OPTION]... --mode=execute COMMAND [ARGS]...

Automatically set library path, then run a program.

This mode accepts the following additional options:

  -dlopen FILE      add the directory containing FILE to the library path

This mode sets the library path environment variable according to \`-dlopen'
flags.

If any of the ARGS are libtool executable wrappers, then they are translated
into their corresponding uninstalled binary, and any of their required library
directories are added to the library path.

Then, COMMAND is executed, with ARGS as arguments."
        ;;

      finish)
        $ECHO \
"Usage: $progname [OPTION]... --mode=finish [LIBDIR]...

Complete the installation of libtool libraries.

Each LIBDIR is a directory that contains libtool libraries.

The commands that this mode executes may require superuser privileges.  Use
the \`--dry-run' option if you just want to see what would be executed."
        ;;

      install)
        $ECHO \
"Usage: $progname [OPTION]... --mode=install INSTALL-COMMAND...

Install executables or libraries.

INSTALL-COMMAND is the installation command.  The first component should be
either the \`install' or \`cp' program.

The following components of INSTALL-COMMAND are treated specially:

  -inst-prefix PREFIX-DIR  Use PREFIX-DIR as a staging area for installation

The rest of the components are interpreted as arguments to that command (only
BSD-compatible install options are recognized)."
        ;;

      link)
        $ECHO \
"Usage: $progname [OPTION]... --mode=link LINK-COMMAND...

Link object files or libraries together to form another library, or to
create an executable program.

LINK-COMMAND is a command using the C compiler that you would use to create
a program from several object files.

The following components of LINK-COMMAND are treated specially:

  -all-static       do not do any dynamic linking at all
  -avoid-version    do not add a version suffix if possible
  -dlopen FILE      \`-dlpreopen' FILE if it cannot be dlopened at runtime
  -dlpreopen FILE   link in FILE and add its symbols to lt_preloaded_symbols
  -export-dynamic   allow symbols from OUTPUT-FILE to be resolved with dlsym(3)
  -export-symbols SYMFILE
                    try to export only the symbols listed in SYMFILE
  -export-symbols-regex REGEX
                    try to export only the symbols matching REGEX
  -LLIBDIR          search LIBDIR for required installed libraries
  -lNAME            OUTPUT-FILE requires the installed library libNAME
  -module           build a library that can dlopened
  -no-fast-install  disable the fast-install mode
  -no-install       link a not-installable executable
  -no-undefined     declare that a library does not refer to external symbols
  -o OUTPUT-FILE    create OUTPUT-FILE from the specified objects
  -objectlist FILE  Use a list of object files found in FILE to specify objects
  -precious-files-regex REGEX
                    don't remove output files matching REGEX
  -release RELEASE  specify package release information
  -rpath LIBDIR     the created library will eventually be installed in LIBDIR
  -R[ ]LIBDIR       add LIBDIR to the runtime path of programs and libraries
  -shared           only do dynamic linking of libtool libraries
  -shrext SUFFIX    override the standard shared library file extension
  -static           do not do any dynamic linking of uninstalled libtool libraries
  -static-libtool-libs
                    do not do any dynamic linking of libtool libraries
  -version-info CURRENT[:REVISION[:AGE]]
                    specify library version info [each variable defaults to 0]
  -weak LIBNAME     declare that the target provides the LIBNAME interface

All other options (arguments beginning with \`-') are ignored.

Every other argument is treated as a filename.  Files ending in \`.la' are
treated as uninstalled libtool libraries, other files are standard or library
object files.

If the OUTPUT-FILE ends in \`.la', then a libtool library is created,
only library objects (\`.lo' files) may be specified, and \`-rpath' is
required, except when creating a convenience library.

If OUTPUT-FILE ends in \`.a' or \`.lib', then a standard library is created
using \`ar' and \`ranlib', or on Windows using \`lib'.

If OUTPUT-FILE ends in \`.lo' or \`.${objext}', then a reloadable object file
is created, otherwise an executable program is created."
        ;;

      uninstall)
        $ECHO \
"Usage: $progname [OPTION]... --mode=uninstall RM [RM-OPTION]... FILE...

Remove libraries from an installation directory.

RM is the name of the program to use to delete files associated with each FILE
(typically \`/bin/rm').  RM-OPTIONS are options (such as \`-f') to be passed
to RM.

If FILE is a libtool library, all the files associated with it are deleted.
Otherwise, only FILE itself is deleted using RM."
        ;;

      *)
        func_fatal_help "invalid operation mode \`$mode'"
        ;;
    esac

    $ECHO
    $ECHO "Try \`$progname --help' for more information about other modes."

    exit $?
}

  # Now that we've collected a possible --mode arg, show help if necessary
  $opt_help && func_mode_help


# func_mode_execute arg...
func_mode_execute ()
{
    $opt_debug
    # The first argument is the command name.
    cmd="$nonopt"
    test -z "$cmd" && \
      func_fatal_help "you must specify a COMMAND"

    # Handle -dlopen flags immediately.
    for file in $execute_dlfiles; do
      test -f "$file" \
	|| func_fatal_help "\`$file' is not a file"

      dir=
      case $file in
      *.la)
	# Check to see that this really is a libtool archive.
	func_lalib_unsafe_p "$file" \
	  || func_fatal_help "\`$lib' is not a valid libtool archive"

	# Read the libtool library.
	dlname=
	library_names=
	func_source "$file"

	# Skip this library if it cannot be dlopened.
	if test -z "$dlname"; then
	  # Warn if it was a shared library.
	  test -n "$library_names" && \
	    func_warning "\`$file' was not linked with \`-export-dynamic'"
	  continue
	fi

	func_dirname "$file" "" "."
	dir="$func_dirname_result"

	if test -f "$dir/$objdir/$dlname"; then
	  dir="$dir/$objdir"
	else
	  if test ! -f "$dir/$dlname"; then
	    func_fatal_error "cannot find \`$dlname' in \`$dir' or \`$dir/$objdir'"
	  fi
	fi
	;;

      *.lo)
	# Just add the directory containing the .lo file.
	func_dirname "$file" "" "."
	dir="$func_dirname_result"
	;;

      *)
	func_warning "\`-dlopen' is ignored for non-libtool libraries and objects"
	continue
	;;
      esac

      # Get the absolute pathname.
      absdir=`cd "$dir" && pwd`
      test -n "$absdir" && dir="$absdir"

      # Now add the directory to shlibpath_var.
      if eval "test -z \"\$$shlibpath_var\""; then
	eval "$shlibpath_var=\"\$dir\""
      else
	eval "$shlibpath_var=\"\$dir:\$$shlibpath_var\""
      fi
    done

    # This variable tells wrapper scripts just to set shlibpath_var
    # rather than running their programs.
    libtool_execute_magic="$magic"

    # Check if any of the arguments is a wrapper script.
    args=
    for file
    do
      case $file in
      -*) ;;
      *)
	# Do a test to see if this is really a libtool program.
	if func_ltwrapper_script_p "$file"; then
	  func_source "$file"
	  # Transform arg to wrapped name.
	  file="$progdir/$program"
	elif func_ltwrapper_executable_p "$file"; then
	  func_ltwrapper_scriptname "$file"
	  func_source "$func_ltwrapper_scriptname_result"
	  # Transform arg to wrapped name.
	  file="$progdir/$program"
	fi
	;;
      esac
      # Quote arguments (to preserve shell metacharacters).
      func_quote_for_eval "$file"
      args="$args $func_quote_for_eval_result"
    done

    if test "X$opt_dry_run" = Xfalse; then
      if test -n "$shlibpath_var"; then
	# Export the shlibpath_var.
	eval "export $shlibpath_var"
      fi

      # Restore saved environment variables
      for lt_var in LANG LANGUAGE LC_ALL LC_CTYPE LC_COLLATE LC_MESSAGES
      do
	eval "if test \"\${save_$lt_var+set}\" = set; then
                $lt_var=\$save_$lt_var; export $lt_var
	      else
		$lt_unset $lt_var
	      fi"
      done

      # Now prepare to actually exec the command.
      exec_cmd="\$cmd$args"
    else
      # Display what would be done.
      if test -n "$shlibpath_var"; then
	eval "\$ECHO \"\$shlibpath_var=\$$shlibpath_var\""
	$ECHO "export $shlibpath_var"
      fi
      $ECHO "$cmd$args"
      exit $EXIT_SUCCESS
    fi
}

test "$mode" = execute && func_mode_execute ${1+"$@"}


# func_mode_finish arg...
func_mode_finish ()
{
    $opt_debug
    libdirs="$nonopt"
    admincmds=

    if test -n "$finish_cmds$finish_eval" && test -n "$libdirs"; then
      for dir
      do
	libdirs="$libdirs $dir"
      done

      for libdir in $libdirs; do
	if test -n "$finish_cmds"; then
	  # Do each command in the finish commands.
	  func_execute_cmds "$finish_cmds" 'admincmds="$admincmds
'"$cmd"'"'
	fi
	if test -n "$finish_eval"; then
	  # Do the single finish_eval.
	  eval cmds=\"$finish_eval\"
	  $opt_dry_run || eval "$cmds" || admincmds="$admincmds
       $cmds"
	fi
      done
    fi

    # Exit here if they wanted silent mode.
    $opt_silent && exit $EXIT_SUCCESS

    $ECHO "X----------------------------------------------------------------------" | $Xsed
    $ECHO "Libraries have been installed in:"
    for libdir in $libdirs; do
      $ECHO "   $libdir"
    done
    $ECHO
    $ECHO "If you ever happen to want to link against installed libraries"
    $ECHO "in a given directory, LIBDIR, you must either use libtool, and"
    $ECHO "specify the full pathname of the library, or use the \`-LLIBDIR'"
    $ECHO "flag during linking and do at least one of the following:"
    if test -n "$shlibpath_var"; then
      $ECHO "   - add LIBDIR to the \`$shlibpath_var' environment variable"
      $ECHO "     during execution"
    fi
    if test -n "$runpath_var"; then
      $ECHO "   - add LIBDIR to the \`$runpath_var' environment variable"
      $ECHO "     during linking"
    fi
    if test -n "$hardcode_libdir_flag_spec"; then
      libdir=LIBDIR
      eval flag=\"$hardcode_libdir_flag_spec\"

      $ECHO "   - use the \`$flag' linker flag"
    fi
    if test -n "$admincmds"; then
      $ECHO "   - have your system administrator run these commands:$admincmds"
    fi
    if test -f /etc/ld.so.conf; then
      $ECHO "   - have your system administrator add LIBDIR to \`/etc/ld.so.conf'"
    fi
    $ECHO

    $ECHO "See any operating system documentation about shared libraries for"
    case $host in
      solaris2.[6789]|solaris2.1[0-9])
        $ECHO "more information, such as the ld(1), crle(1) and ld.so(8) manual"
	$ECHO "pages."
	;;
      *)
        $ECHO "more information, such as the ld(1) and ld.so(8) manual pages."
        ;;
    esac
    $ECHO "X----------------------------------------------------------------------" | $Xsed
    exit $EXIT_SUCCESS
}

test "$mode" = finish && func_mode_finish ${1+"$@"}


# func_mode_install arg...
func_mode_install ()
{
    $opt_debug
    # There may be an optional sh(1) argument at the beginning of
    # install_prog (especially on Windows NT).
    if test "$nonopt" = "$SHELL" || test "$nonopt" = /bin/sh ||
       # Allow the use of GNU shtool's install command.
       $ECHO "X$nonopt" | $GREP shtool >/dev/null; then
      # Aesthetically quote it.
      func_quote_for_eval "$nonopt"
      install_prog="$func_quote_for_eval_result "
      arg=$1
      shift
    else
      install_prog=
      arg=$nonopt
    fi

    # The real first argument should be the name of the installation program.
    # Aesthetically quote it.
    func_quote_for_eval "$arg"
    install_prog="$install_prog$func_quote_for_eval_result"

    # We need to accept at least all the BSD install flags.
    dest=
    files=
    opts=
    prev=
    install_type=
    isdir=no
    stripme=
    for arg
    do
      if test -n "$dest"; then
	files="$files $dest"
	dest=$arg
	continue
      fi

      case $arg in
      -d) isdir=yes ;;
      -f)
	case " $install_prog " in
	*[\\\ /]cp\ *) ;;
	*) prev=$arg ;;
	esac
	;;
      -g | -m | -o)
	prev=$arg
	;;
      -s)
	stripme=" -s"
	continue
	;;
      -*)
	;;
      *)
	# If the previous option needed an argument, then skip it.
	if test -n "$prev"; then
	  prev=
	else
	  dest=$arg
	  continue
	fi
	;;
      esac

      # Aesthetically quote the argument.
      func_quote_for_eval "$arg"
      install_prog="$install_prog $func_quote_for_eval_result"
    done

    test -z "$install_prog" && \
      func_fatal_help "you must specify an install program"

    test -n "$prev" && \
      func_fatal_help "the \`$prev' option requires an argument"

    if test -z "$files"; then
      if test -z "$dest"; then
	func_fatal_help "no file or destination specified"
      else
	func_fatal_help "you must specify a destination"
      fi
    fi

    # Strip any trailing slash from the destination.
    func_stripname '' '/' "$dest"
    dest=$func_stripname_result

    # Check to see that the destination is a directory.
    test -d "$dest" && isdir=yes
    if test "$isdir" = yes; then
      destdir="$dest"
      destname=
    else
      func_dirname_and_basename "$dest" "" "."
      destdir="$func_dirname_result"
      destname="$func_basename_result"

      # Not a directory, so check to see that there is only one file specified.
      set dummy $files; shift
      test "$#" -gt 1 && \
	func_fatal_help "\`$dest' is not a directory"
    fi
    case $destdir in
    [\\/]* | [A-Za-z]:[\\/]*) ;;
    *)
      for file in $files; do
	case $file in
	*.lo) ;;
	*)
	  func_fatal_help "\`$destdir' must be an absolute directory name"
	  ;;
	esac
      done
      ;;
    esac

    # This variable tells wrapper scripts just to set variables rather
    # than running their programs.
    libtool_install_magic="$magic"

    staticlibs=
    future_libdirs=
    current_libdirs=
    for file in $files; do

      # Do each installation.
      case $file in
      *.$libext)
	# Do the static libraries later.
	staticlibs="$staticlibs $file"
	;;

      *.la)
	# Check to see that this really is a libtool archive.
	func_lalib_unsafe_p "$file" \
	  || func_fatal_help "\`$file' is not a valid libtool archive"

	library_names=
	old_library=
	relink_command=
	func_source "$file"

	# Add the libdir to current_libdirs if it is the destination.
	if test "X$destdir" = "X$libdir"; then
	  case "$current_libdirs " in
	  *" $libdir "*) ;;
	  *) current_libdirs="$current_libdirs $libdir" ;;
	  esac
	else
	  # Note the libdir as a future libdir.
	  case "$future_libdirs " in
	  *" $libdir "*) ;;
	  *) future_libdirs="$future_libdirs $libdir" ;;
	  esac
	fi

	func_dirname "$file" "/" ""
	dir="$func_dirname_result"
	dir="$dir$objdir"

	if test -n "$relink_command"; then
	  # Determine the prefix the user has applied to our future dir.
	  inst_prefix_dir=`$ECHO "X$destdir" | $Xsed -e "s%$libdir\$%%"`

	  # Don't allow the user to place us outside of our expected
	  # location b/c this prevents finding dependent libraries that
	  # are installed to the same prefix.
	  # At present, this check doesn't affect windows .dll's that
	  # are installed into $libdir/../bin (currently, that works fine)
	  # but it's something to keep an eye on.
	  test "$inst_prefix_dir" = "$destdir" && \
	    func_fatal_error "error: cannot install \`$file' to a directory not ending in $libdir"

	  if test -n "$inst_prefix_dir"; then
	    # Stick the inst_prefix_dir data into the link command.
	    relink_command=`$ECHO "X$relink_command" | $Xsed -e "s%@inst_prefix_dir@%-inst-prefix-dir $inst_prefix_dir%"`
	  else
	    relink_command=`$ECHO "X$relink_command" | $Xsed -e "s%@inst_prefix_dir@%%"`
	  fi

	  func_warning "relinking \`$file'"
	  func_show_eval "$relink_command" \
	    'func_fatal_error "error: relink \`$file'\'' with the above command before installing it"'
	fi

	# See the names of the shared library.
	set dummy $library_names; shift
	if test -n "$1"; then
	  realname="$1"
	  shift

	  srcname="$realname"
	  test -n "$relink_command" && srcname="$realname"T

	  # Install the shared library and build the symlinks.
	  func_show_eval "$install_prog $dir/$srcname $destdir/$realname" \
	      'exit $?'
	  tstripme="$stripme"
	  case $host_os in
	  cygwin* | mingw* | pw32* | cegcc*)
	    case $realname in
	    *.dll.a)
	      tstripme=""
	      ;;
	    esac
	    ;;
	  esac
	  if test -n "$tstripme" && test -n "$striplib"; then
	    func_show_eval "$striplib $destdir/$realname" 'exit $?'
	  fi

	  if test "$#" -gt 0; then
	    # Delete the old symlinks, and create new ones.
	    # Try `ln -sf' first, because the `ln' binary might depend on
	    # the symlink we replace!  Solaris /bin/ln does not understand -f,
	    # so we also need to try rm && ln -s.
	    for linkname
	    do
	      test "$linkname" != "$realname" \
		&& func_show_eval "(cd $destdir && { $LN_S -f $realname $linkname || { $RM $linkname && $LN_S $realname $linkname; }; })"
	    done
	  fi

	  # Do each command in the postinstall commands.
	  lib="$destdir/$realname"
	  func_execute_cmds "$postinstall_cmds" 'exit $?'
	fi

	# Install the pseudo-library for information purposes.
	func_basename "$file"
	name="$func_basename_result"
	instname="$dir/$name"i
	func_show_eval "$install_prog $instname $destdir/$name" 'exit $?'

	# Maybe install the static library, too.
	test -n "$old_library" && staticlibs="$staticlibs $dir/$old_library"
	;;

      *.lo)
	# Install (i.e. copy) a libtool object.

	# Figure out destination file name, if it wasn't already specified.
	if test -n "$destname"; then
	  destfile="$destdir/$destname"
	else
	  func_basename "$file"
	  destfile="$func_basename_result"
	  destfile="$destdir/$destfile"
	fi

	# Deduce the name of the destination old-style object file.
	case $destfile in
	*.lo)
	  func_lo2o "$destfile"
	  staticdest=$func_lo2o_result
	  ;;
	*.$objext)
	  staticdest="$destfile"
	  destfile=
	  ;;
	*)
	  func_fatal_help "cannot copy a libtool object to \`$destfile'"
	  ;;
	esac

	# Install the libtool object if requested.
	test -n "$destfile" && \
	  func_show_eval "$install_prog $file $destfile" 'exit $?'

	# Install the old object if enabled.
	if test "$build_old_libs" = yes; then
	  # Deduce the name of the old-style object file.
	  func_lo2o "$file"
	  staticobj=$func_lo2o_result
	  func_show_eval "$install_prog \$staticobj \$staticdest" 'exit $?'
	fi
	exit $EXIT_SUCCESS
	;;

      *)
	# Figure out destination file name, if it wasn't already specified.
	if test -n "$destname"; then
	  destfile="$destdir/$destname"
	else
	  func_basename "$file"
	  destfile="$func_basename_result"
	  destfile="$destdir/$destfile"
	fi

	# If the file is missing, and there is a .exe on the end, strip it
	# because it is most likely a libtool script we actually want to
	# install
	stripped_ext=""
	case $file in
	  *.exe)
	    if test ! -f "$file"; then
	      func_stripname '' '.exe' "$file"
	      file=$func_stripname_result
	      stripped_ext=".exe"
	    fi
	    ;;
	esac

	# Do a test to see if this is really a libtool program.
	case $host in
	*cygwin* | *mingw*)
	    if func_ltwrapper_executable_p "$file"; then
	      func_ltwrapper_scriptname "$file"
	      wrapper=$func_ltwrapper_scriptname_result
	    else
	      func_stripname '' '.exe' "$file"
	      wrapper=$func_stripname_result
	    fi
	    ;;
	*)
	    wrapper=$file
	    ;;
	esac
	if func_ltwrapper_script_p "$wrapper"; then
	  notinst_deplibs=
	  relink_command=

	  func_source "$wrapper"

	  # Check the variables that should have been set.
	  test -z "$generated_by_libtool_version" && \
	    func_fatal_error "invalid libtool wrapper script \`$wrapper'"

	  finalize=yes
	  for lib in $notinst_deplibs; do
	    # Check to see that each library is installed.
	    libdir=
	    if test -f "$lib"; then
	      func_source "$lib"
	    fi
	    libfile="$libdir/"`$ECHO "X$lib" | $Xsed -e 's%^.*/%%g'` ### testsuite: skip nested quoting test
	    if test -n "$libdir" && test ! -f "$libfile"; then
	      func_warning "\`$lib' has not been installed in \`$libdir'"
	      finalize=no
	    fi
	  done

	  relink_command=
	  func_source "$wrapper"

	  outputname=
	  if test "$fast_install" = no && test -n "$relink_command"; then
	    $opt_dry_run || {
	      if test "$finalize" = yes; then
	        tmpdir=`func_mktempdir`
		func_basename "$file$stripped_ext"
		file="$func_basename_result"
	        outputname="$tmpdir/$file"
	        # Replace the output file specification.
	        relink_command=`$ECHO "X$relink_command" | $Xsed -e 's%@OUTPUT@%'"$outputname"'%g'`

	        $opt_silent || {
	          func_quote_for_expand "$relink_command"
		  eval "func_echo $func_quote_for_expand_result"
	        }
	        if eval "$relink_command"; then :
	          else
		  func_error "error: relink \`$file' with the above command before installing it"
		  $opt_dry_run || ${RM}r "$tmpdir"
		  continue
	        fi
	        file="$outputname"
	      else
	        func_warning "cannot relink \`$file'"
	      fi
	    }
	  else
	    # Install the binary that we compiled earlier.
	    file=`$ECHO "X$file$stripped_ext" | $Xsed -e "s%\([^/]*\)$%$objdir/\1%"`
	  fi
	fi

	# remove .exe since cygwin /usr/bin/install will append another
	# one anyway
	case $install_prog,$host in
	*/usr/bin/install*,*cygwin*)
	  case $file:$destfile in
	  *.exe:*.exe)
	    # this is ok
	    ;;
	  *.exe:*)
	    destfile=$destfile.exe
	    ;;
	  *:*.exe)
	    func_stripname '' '.exe' "$destfile"
	    destfile=$func_stripname_result
	    ;;
	  esac
	  ;;
	esac
	func_show_eval "$install_prog\$stripme \$file \$destfile" 'exit $?'
	$opt_dry_run || if test -n "$outputname"; then
	  ${RM}r "$tmpdir"
	fi
	;;
      esac
    done

    for file in $staticlibs; do
      func_basename "$file"
      name="$func_basename_result"

      # Set up the ranlib parameters.
      oldlib="$destdir/$name"

      func_show_eval "$install_prog \$file \$oldlib" 'exit $?'

      if test -n "$stripme" && test -n "$old_striplib"; then
	func_show_eval "$old_striplib $oldlib" 'exit $?'
      fi

      # Do each command in the postinstall commands.
      func_execute_cmds "$old_postinstall_cmds" 'exit $?'
    done

    test -n "$future_libdirs" && \
      func_warning "remember to run \`$progname --finish$future_libdirs'"

    if test -n "$current_libdirs"; then
      # Maybe just do a dry run.
      $opt_dry_run && current_libdirs=" -n$current_libdirs"
      exec_cmd='$SHELL $progpath $preserve_args --finish$current_libdirs'
    else
      exit $EXIT_SUCCESS
    fi
}

test "$mode" = install && func_mode_install ${1+"$@"}


# func_generate_dlsyms outputname originator pic_p
# Extract symbols from dlprefiles and create ${outputname}S.o with
# a dlpreopen symbol table.
func_generate_dlsyms ()
{
    $opt_debug
    my_outputname="$1"
    my_originator="$2"
    my_pic_p="${3-no}"
    my_prefix=`$ECHO "$my_originator" | sed 's%[^a-zA-Z0-9]%_%g'`
    my_dlsyms=

    if test -n "$dlfiles$dlprefiles" || test "$dlself" != no; then
      if test -n "$NM" && test -n "$global_symbol_pipe"; then
	my_dlsyms="${my_outputname}S.c"
      else
	func_error "not configured to extract global symbols from dlpreopened files"
      fi
    fi

    if test -n "$my_dlsyms"; then
      case $my_dlsyms in
      "") ;;
      *.c)
	# Discover the nlist of each of the dlfiles.
	nlist="$output_objdir/${my_outputname}.nm"

	func_show_eval "$RM $nlist ${nlist}S ${nlist}T"

	# Parse the name list into a source file.
	func_verbose "creating $output_objdir/$my_dlsyms"

	$opt_dry_run || $ECHO > "$output_objdir/$my_dlsyms" "\
/* $my_dlsyms - symbol resolution table for \`$my_outputname' dlsym emulation. */
/* Generated by $PROGRAM (GNU $PACKAGE$TIMESTAMP) $VERSION */

#ifdef __cplusplus
extern \"C\" {
#endif

/* External symbol declarations for the compiler. */\
"

	if test "$dlself" = yes; then
	  func_verbose "generating symbol list for \`$output'"

	  $opt_dry_run || echo ': @PROGRAM@ ' > "$nlist"

	  # Add our own program objects to the symbol list.
	  progfiles=`$ECHO "X$objs$old_deplibs" | $SP2NL | $Xsed -e "$lo2o" | $NL2SP`
	  for progfile in $progfiles; do
	    func_verbose "extracting global C symbols from \`$progfile'"
	    $opt_dry_run || eval "$NM $progfile | $global_symbol_pipe >> '$nlist'"
	  done

	  if test -n "$exclude_expsyms"; then
	    $opt_dry_run || {
	      eval '$EGREP -v " ($exclude_expsyms)$" "$nlist" > "$nlist"T'
	      eval '$MV "$nlist"T "$nlist"'
	    }
	  fi

	  if test -n "$export_symbols_regex"; then
	    $opt_dry_run || {
	      eval '$EGREP -e "$export_symbols_regex" "$nlist" > "$nlist"T'
	      eval '$MV "$nlist"T "$nlist"'
	    }
	  fi

	  # Prepare the list of exported symbols
	  if test -z "$export_symbols"; then
	    export_symbols="$output_objdir/$outputname.exp"
	    $opt_dry_run || {
	      $RM $export_symbols
	      eval "${SED} -n -e '/^: @PROGRAM@ $/d' -e 's/^.* \(.*\)$/\1/p' "'< "$nlist" > "$export_symbols"'
	      case $host in
	      *cygwin* | *mingw* | *cegcc* )
                eval "echo EXPORTS "'> "$output_objdir/$outputname.def"'
                eval 'cat "$export_symbols" >> "$output_objdir/$outputname.def"'
	        ;;
	      esac
	    }
	  else
	    $opt_dry_run || {
	      eval "${SED} -e 's/\([].[*^$]\)/\\\\\1/g' -e 's/^/ /' -e 's/$/$/'"' < "$export_symbols" > "$output_objdir/$outputname.exp"'
	      eval '$GREP -f "$output_objdir/$outputname.exp" < "$nlist" > "$nlist"T'
	      eval '$MV "$nlist"T "$nlist"'
	      case $host in
	        *cygwin | *mingw* | *cegcc* )
	          eval "echo EXPORTS "'> "$output_objdir/$outputname.def"'
	          eval 'cat "$nlist" >> "$output_objdir/$outputname.def"'
	          ;;
	      esac
	    }
	  fi
	fi

	for dlprefile in $dlprefiles; do
	  func_verbose "extracting global C symbols from \`$dlprefile'"
	  func_basename "$dlprefile"
	  name="$func_basename_result"
	  $opt_dry_run || {
	    eval '$ECHO ": $name " >> "$nlist"'
	    eval "$NM $dlprefile 2>/dev/null | $global_symbol_pipe >> '$nlist'"
	  }
	done

	$opt_dry_run || {
	  # Make sure we have at least an empty file.
	  test -f "$nlist" || : > "$nlist"

	  if test -n "$exclude_expsyms"; then
	    $EGREP -v " ($exclude_expsyms)$" "$nlist" > "$nlist"T
	    $MV "$nlist"T "$nlist"
	  fi

	  # Try sorting and uniquifying the output.
	  if $GREP -v "^: " < "$nlist" |
	      if sort -k 3 </dev/null >/dev/null 2>&1; then
		sort -k 3
	      else
		sort +2
	      fi |
	      uniq > "$nlist"S; then
	    :
	  else
	    $GREP -v "^: " < "$nlist" > "$nlist"S
	  fi

	  if test -f "$nlist"S; then
	    eval "$global_symbol_to_cdecl"' < "$nlist"S >> "$output_objdir/$my_dlsyms"'
	  else
	    $ECHO '/* NONE */' >> "$output_objdir/$my_dlsyms"
	  fi

	  $ECHO >> "$output_objdir/$my_dlsyms" "\

/* The mapping between symbol names and symbols.  */
typedef struct {
  const char *name;
  void *address;
} lt_dlsymlist;
"
	  case $host in
	  *cygwin* | *mingw* | *cegcc* )
	    $ECHO >> "$output_objdir/$my_dlsyms" "\
/* DATA imports from DLLs on WIN32 con't be const, because
   runtime relocations are performed -- see ld's documentation
   on pseudo-relocs.  */"
	    lt_dlsym_const= ;;
	  *osf5*)
	    echo >> "$output_objdir/$my_dlsyms" "\
/* This system does not cope well with relocations in const data */"
	    lt_dlsym_const= ;;
	  *)
	    lt_dlsym_const=const ;;
	  esac

	  $ECHO >> "$output_objdir/$my_dlsyms" "\
extern $lt_dlsym_const lt_dlsymlist
lt_${my_prefix}_LTX_preloaded_symbols[];
$lt_dlsym_const lt_dlsymlist
lt_${my_prefix}_LTX_preloaded_symbols[] =
{\
  { \"$my_originator\", (void *) 0 },"

	  case $need_lib_prefix in
	  no)
	    eval "$global_symbol_to_c_name_address" < "$nlist" >> "$output_objdir/$my_dlsyms"
	    ;;
	  *)
	    eval "$global_symbol_to_c_name_address_lib_prefix" < "$nlist" >> "$output_objdir/$my_dlsyms"
	    ;;
	  esac
	  $ECHO >> "$output_objdir/$my_dlsyms" "\
  {0, (void *) 0}
};

/* This works around a problem in FreeBSD linker */
#ifdef FREEBSD_WORKAROUND
static const void *lt_preloaded_setup() {
  return lt_${my_prefix}_LTX_preloaded_symbols;
}
#endif

#ifdef __cplusplus
}
#endif\
"
	} # !$opt_dry_run

	pic_flag_for_symtable=
	case "$compile_command " in
	*" -static "*) ;;
	*)
	  case $host in
	  # compiling the symbol table file with pic_flag works around
	  # a FreeBSD bug that causes programs to crash when -lm is
	  # linked before any other PIC object.  But we must not use
	  # pic_flag when linking with -static.  The problem exists in
	  # FreeBSD 2.2.6 and is fixed in FreeBSD 3.1.
	  *-*-freebsd2*|*-*-freebsd3.0*|*-*-freebsdelf3.0*)
	    pic_flag_for_symtable=" $pic_flag -DFREEBSD_WORKAROUND" ;;
	  *-*-hpux*)
	    pic_flag_for_symtable=" $pic_flag"  ;;
	  *)
	    if test "X$my_pic_p" != Xno; then
	      pic_flag_for_symtable=" $pic_flag"
	    fi
	    ;;
	  esac
	  ;;
	esac
	symtab_cflags=
	for arg in $LTCFLAGS; do
	  case $arg in
	  -pie | -fpie | -fPIE) ;;
	  *) symtab_cflags="$symtab_cflags $arg" ;;
	  esac
	done

	# Now compile the dynamic symbol file.
	func_show_eval '(cd $output_objdir && $LTCC$symtab_cflags -c$no_builtin_flag$pic_flag_for_symtable "$my_dlsyms")' 'exit $?'

	# Clean up the generated files.
	func_show_eval '$RM "$output_objdir/$my_dlsyms" "$nlist" "${nlist}S" "${nlist}T"'

	# Transform the symbol file into the correct name.
	symfileobj="$output_objdir/${my_outputname}S.$objext"
	case $host in
	*cygwin* | *mingw* | *cegcc* )
	  if test -f "$output_objdir/$my_outputname.def"; then
	    compile_command=`$ECHO "X$compile_command" | $Xsed -e "s%@SYMFILE@%$output_objdir/$my_outputname.def $symfileobj%"`
	    finalize_command=`$ECHO "X$finalize_command" | $Xsed -e "s%@SYMFILE@%$output_objdir/$my_outputname.def $symfileobj%"`
	  else
	    compile_command=`$ECHO "X$compile_command" | $Xsed -e "s%@SYMFILE@%$symfileobj%"`
	    finalize_command=`$ECHO "X$finalize_command" | $Xsed -e "s%@SYMFILE@%$symfileobj%"`
	  fi
	  ;;
	*)
	  compile_command=`$ECHO "X$compile_command" | $Xsed -e "s%@SYMFILE@%$symfileobj%"`
	  finalize_command=`$ECHO "X$finalize_command" | $Xsed -e "s%@SYMFILE@%$symfileobj%"`
	  ;;
	esac
	;;
      *)
	func_fatal_error "unknown suffix for \`$my_dlsyms'"
	;;
      esac
    else
      # We keep going just in case the user didn't refer to
      # lt_preloaded_symbols.  The linker will fail if global_symbol_pipe
      # really was required.

      # Nullify the symbol file.
      compile_command=`$ECHO "X$compile_command" | $Xsed -e "s% @SYMFILE@%%"`
      finalize_command=`$ECHO "X$finalize_command" | $Xsed -e "s% @SYMFILE@%%"`
    fi
}

# func_win32_libid arg
# return the library type of file 'arg'
#
# Need a lot of goo to handle *both* DLLs and import libs
# Has to be a shell function in order to 'eat' the argument
# that is supplied when $file_magic_command is called.
func_win32_libid ()
{
  $opt_debug
  win32_libid_type="unknown"
  win32_fileres=`file -L $1 2>/dev/null`
  case $win32_fileres in
  *ar\ archive\ import\ library*) # definitely import
    win32_libid_type="x86 archive import"
    ;;
  *ar\ archive*) # could be an import, or static
    if eval $OBJDUMP -f $1 | $SED -e '10q' 2>/dev/null |
       $EGREP 'file format pe-i386(.*architecture: i386)?' >/dev/null ; then
      win32_nmres=`eval $NM -f posix -A $1 |
	$SED -n -e '
	    1,100{
		/ I /{
		    s,.*,import,
		    p
		    q
		}
	    }'`
      case $win32_nmres in
      import*)  win32_libid_type="x86 archive import";;
      *)        win32_libid_type="x86 archive static";;
      esac
    fi
    ;;
  *DLL*)
    win32_libid_type="x86 DLL"
    ;;
  *executable*) # but shell scripts are "executable" too...
    case $win32_fileres in
    *MS\ Windows\ PE\ Intel*)
      win32_libid_type="x86 DLL"
      ;;
    esac
    ;;
  esac
  $ECHO "$win32_libid_type"
}



# func_extract_an_archive dir oldlib
func_extract_an_archive ()
{
    $opt_debug
    f_ex_an_ar_dir="$1"; shift
    f_ex_an_ar_oldlib="$1"
    func_show_eval "(cd \$f_ex_an_ar_dir && $AR x \"\$f_ex_an_ar_oldlib\")" 'exit $?'
    if ($AR t "$f_ex_an_ar_oldlib" | sort | sort -uc >/dev/null 2>&1); then
     :
    else
      func_fatal_error "object name conflicts in archive: $f_ex_an_ar_dir/$f_ex_an_ar_oldlib"
    fi
}


# func_extract_archives gentop oldlib ...
func_extract_archives ()
{
    $opt_debug
    my_gentop="$1"; shift
    my_oldlibs=${1+"$@"}
    my_oldobjs=""
    my_xlib=""
    my_xabs=""
    my_xdir=""

    for my_xlib in $my_oldlibs; do
      # Extract the objects.
      case $my_xlib in
	[\\/]* | [A-Za-z]:[\\/]*) my_xabs="$my_xlib" ;;
	*) my_xabs=`pwd`"/$my_xlib" ;;
      esac
      func_basename "$my_xlib"
      my_xlib="$func_basename_result"
      my_xlib_u=$my_xlib
      while :; do
        case " $extracted_archives " in
	*" $my_xlib_u "*)
	  func_arith $extracted_serial + 1
	  extracted_serial=$func_arith_result
	  my_xlib_u=lt$extracted_serial-$my_xlib ;;
	*) break ;;
	esac
      done
      extracted_archives="$extracted_archives $my_xlib_u"
      my_xdir="$my_gentop/$my_xlib_u"

      func_mkdir_p "$my_xdir"

      case $host in
      *-darwin*)
	func_verbose "Extracting $my_xabs"
	# Do not bother doing anything if just a dry run
	$opt_dry_run || {
	  darwin_orig_dir=`pwd`
	  cd $my_xdir || exit $?
	  darwin_archive=$my_xabs
	  darwin_curdir=`pwd`
	  darwin_base_archive=`basename "$darwin_archive"`
	  darwin_arches=`$LIPO -info "$darwin_archive" 2>/dev/null | $GREP Architectures 2>/dev/null || true`
	  if test -n "$darwin_arches"; then
	    darwin_arches=`$ECHO "$darwin_arches" | $SED -e 's/.*are://'`
	    darwin_arch=
	    func_verbose "$darwin_base_archive has multiple architectures $darwin_arches"
	    for darwin_arch in  $darwin_arches ; do
	      func_mkdir_p "unfat-$$/${darwin_base_archive}-${darwin_arch}"
	      $LIPO -thin $darwin_arch -output "unfat-$$/${darwin_base_archive}-${darwin_arch}/${darwin_base_archive}" "${darwin_archive}"
	      cd "unfat-$$/${darwin_base_archive}-${darwin_arch}"
	      func_extract_an_archive "`pwd`" "${darwin_base_archive}"
	      cd "$darwin_curdir"
	      $RM "unfat-$$/${darwin_base_archive}-${darwin_arch}/${darwin_base_archive}"
	    done # $darwin_arches
            ## Okay now we've a bunch of thin objects, gotta fatten them up :)
	    darwin_filelist=`find unfat-$$ -type f -name \*.o -print -o -name \*.lo -print | $SED -e "$basename" | sort -u`
	    darwin_file=
	    darwin_files=
	    for darwin_file in $darwin_filelist; do
	      darwin_files=`find unfat-$$ -name $darwin_file -print | $NL2SP`
	      $LIPO -create -output "$darwin_file" $darwin_files
	    done # $darwin_filelist
	    $RM -rf unfat-$$
	    cd "$darwin_orig_dir"
	  else
	    cd $darwin_orig_dir
	    func_extract_an_archive "$my_xdir" "$my_xabs"
	  fi # $darwin_arches
	} # !$opt_dry_run
	;;
      *)
        func_extract_an_archive "$my_xdir" "$my_xabs"
	;;
      esac
      my_oldobjs="$my_oldobjs "`find $my_xdir -name \*.$objext -print -o -name \*.lo -print | $NL2SP`
    done

    func_extract_archives_result="$my_oldobjs"
}



# func_emit_wrapper_part1 [arg=no]
#
# Emit the first part of a libtool wrapper script on stdout.
# For more information, see the description associated with
# func_emit_wrapper(), below.
func_emit_wrapper_part1 ()
{
	func_emit_wrapper_part1_arg1=no
	if test -n "$1" ; then
	  func_emit_wrapper_part1_arg1=$1
	fi

	$ECHO "\
#! $SHELL

# $output - temporary wrapper script for $objdir/$outputname
# Generated by $PROGRAM (GNU $PACKAGE$TIMESTAMP) $VERSION
#
# The $output program cannot be directly executed until all the libtool
# libraries that it depends on are installed.
#
# This wrapper script should never be moved out of the build directory.
# If it is, it will not operate correctly.

# Sed substitution that helps us do robust quoting.  It backslashifies
# metacharacters that are still active within double-quoted strings.
Xsed='${SED} -e 1s/^X//'
sed_quote_subst='$sed_quote_subst'

# Be Bourne compatible
if test -n \"\${ZSH_VERSION+set}\" && (emulate sh) >/dev/null 2>&1; then
  emulate sh
  NULLCMD=:
  # Zsh 3.x and 4.x performs word splitting on \${1+\"\$@\"}, which
  # is contrary to our usage.  Disable this feature.
  alias -g '\${1+\"\$@\"}'='\"\$@\"'
  setopt NO_GLOB_SUBST
else
  case \`(set -o) 2>/dev/null\` in *posix*) set -o posix;; esac
fi
BIN_SH=xpg4; export BIN_SH # for Tru64
DUALCASE=1; export DUALCASE # for MKS sh

# The HP-UX ksh and POSIX shell print the target directory to stdout
# if CDPATH is set.
(unset CDPATH) >/dev/null 2>&1 && unset CDPATH

relink_command=\"$relink_command\"

# This environment variable determines our operation mode.
if test \"\$libtool_install_magic\" = \"$magic\"; then
  # install mode needs the following variables:
  generated_by_libtool_version='$macro_version'
  notinst_deplibs='$notinst_deplibs'
else
  # When we are sourced in execute mode, \$file and \$ECHO are already set.
  if test \"\$libtool_execute_magic\" != \"$magic\"; then
    ECHO=\"$qecho\"
    file=\"\$0\"
    # Make sure echo works.
    if test \"X\$1\" = X--no-reexec; then
      # Discard the --no-reexec flag, and continue.
      shift
    elif test \"X\`{ \$ECHO '\t'; } 2>/dev/null\`\" = 'X\t'; then
      # Yippee, \$ECHO works!
      :
    else
      # Restart under the correct shell, and then maybe \$ECHO will work.
      exec $SHELL \"\$0\" --no-reexec \${1+\"\$@\"}
    fi
  fi\
"
	$ECHO "\

  # Find the directory that this script lives in.
  thisdir=\`\$ECHO \"X\$file\" | \$Xsed -e 's%/[^/]*$%%'\`
  test \"x\$thisdir\" = \"x\$file\" && thisdir=.

  # Follow symbolic links until we get to the real thisdir.
  file=\`ls -ld \"\$file\" | ${SED} -n 's/.*-> //p'\`
  while test -n \"\$file\"; do
    destdir=\`\$ECHO \"X\$file\" | \$Xsed -e 's%/[^/]*\$%%'\`

    # If there was a directory component, then change thisdir.
    if test \"x\$destdir\" != \"x\$file\"; then
      case \"\$destdir\" in
      [\\\\/]* | [A-Za-z]:[\\\\/]*) thisdir=\"\$destdir\" ;;
      *) thisdir=\"\$thisdir/\$destdir\" ;;
      esac
    fi

    file=\`\$ECHO \"X\$file\" | \$Xsed -e 's%^.*/%%'\`
    file=\`ls -ld \"\$thisdir/\$file\" | ${SED} -n 's/.*-> //p'\`
  done
"
}
# end: func_emit_wrapper_part1

# func_emit_wrapper_part2 [arg=no]
#
# Emit the second part of a libtool wrapper script on stdout.
# For more information, see the description associated with
# func_emit_wrapper(), below.
func_emit_wrapper_part2 ()
{
	func_emit_wrapper_part2_arg1=no
	if test -n "$1" ; then
	  func_emit_wrapper_part2_arg1=$1
	fi

	$ECHO "\

  # Usually 'no', except on cygwin/mingw when embedded into
  # the cwrapper.
  WRAPPER_SCRIPT_BELONGS_IN_OBJDIR=$func_emit_wrapper_part2_arg1
  if test \"\$WRAPPER_SCRIPT_BELONGS_IN_OBJDIR\" = \"yes\"; then
    # special case for '.'
    if test \"\$thisdir\" = \".\"; then
      thisdir=\`pwd\`
    fi
    # remove .libs from thisdir
    case \"\$thisdir\" in
    *[\\\\/]$objdir ) thisdir=\`\$ECHO \"X\$thisdir\" | \$Xsed -e 's%[\\\\/][^\\\\/]*$%%'\` ;;
    $objdir )   thisdir=. ;;
    esac
  fi

  # Try to get the absolute directory name.
  absdir=\`cd \"\$thisdir\" && pwd\`
  test -n \"\$absdir\" && thisdir=\"\$absdir\"
"

	if test "$fast_install" = yes; then
	  $ECHO "\
  program=lt-'$outputname'$exeext
  progdir=\"\$thisdir/$objdir\"

  if test ! -f \"\$progdir/\$program\" ||
     { file=\`ls -1dt \"\$progdir/\$program\" \"\$progdir/../\$program\" 2>/dev/null | ${SED} 1q\`; \\
       test \"X\$file\" != \"X\$progdir/\$program\"; }; then

    file=\"\$\$-\$program\"

    if test ! -d \"\$progdir\"; then
      $MKDIR \"\$progdir\"
    else
      $RM \"\$progdir/\$file\"
    fi"

	  $ECHO "\

    # relink executable if necessary
    if test -n \"\$relink_command\"; then
      if relink_command_output=\`eval \$relink_command 2>&1\`; then :
      else
	$ECHO \"\$relink_command_output\" >&2
	$RM \"\$progdir/\$file\"
	exit 1
      fi
    fi

    $MV \"\$progdir/\$file\" \"\$progdir/\$program\" 2>/dev/null ||
    { $RM \"\$progdir/\$program\";
      $MV \"\$progdir/\$file\" \"\$progdir/\$program\"; }
    $RM \"\$progdir/\$file\"
  fi"
	else
	  $ECHO "\
  program='$outputname'
  progdir=\"\$thisdir/$objdir\"
"
	fi

	$ECHO "\

  if test -f \"\$progdir/\$program\"; then"

	# Export our shlibpath_var if we have one.
	if test "$shlibpath_overrides_runpath" = yes && test -n "$shlibpath_var" && test -n "$temp_rpath"; then
	  $ECHO "\
    # Add our own library path to $shlibpath_var
    $shlibpath_var=\"$temp_rpath\$$shlibpath_var\"

    # Some systems cannot cope with colon-terminated $shlibpath_var
    # The second colon is a workaround for a bug in BeOS R4 sed
    $shlibpath_var=\`\$ECHO \"X\$$shlibpath_var\" | \$Xsed -e 's/::*\$//'\`

    export $shlibpath_var
"
	fi

	# fixup the dll searchpath if we need to.
	if test -n "$dllsearchpath"; then
	  $ECHO "\
    # Add the dll search path components to the executable PATH
    PATH=$dllsearchpath:\$PATH
"
	fi

	$ECHO "\
    if test \"\$libtool_execute_magic\" != \"$magic\"; then
      # Run the actual program with our arguments.
"
	case $host in
	# Backslashes separate directories on plain windows
	*-*-mingw | *-*-os2* | *-cegcc*)
	  $ECHO "\
      exec \"\$progdir\\\\\$program\" \${1+\"\$@\"}
"
	  ;;

	*)
	  $ECHO "\
      exec \"\$progdir/\$program\" \${1+\"\$@\"}
"
	  ;;
	esac
	$ECHO "\
      \$ECHO \"\$0: cannot exec \$program \$*\" 1>&2
      exit 1
    fi
  else
    # The program doesn't exist.
    \$ECHO \"\$0: error: \\\`\$progdir/\$program' does not exist\" 1>&2
    \$ECHO \"This script is just a wrapper for \$program.\" 1>&2
    $ECHO \"See the $PACKAGE documentation for more information.\" 1>&2
    exit 1
  fi
fi\
"
}
# end: func_emit_wrapper_part2


# func_emit_wrapper [arg=no]
#
# Emit a libtool wrapper script on stdout.
# Don't directly open a file because we may want to
# incorporate the script contents within a cygwin/mingw
# wrapper executable.  Must ONLY be called from within
# func_mode_link because it depends on a number of variables
# set therein.
#
# ARG is the value that the WRAPPER_SCRIPT_BELONGS_IN_OBJDIR
# variable will take.  If 'yes', then the emitted script
# will assume that the directory in which it is stored is
# the $objdir directory.  This is a cygwin/mingw-specific
# behavior.
func_emit_wrapper ()
{
	func_emit_wrapper_arg1=no
	if test -n "$1" ; then
	  func_emit_wrapper_arg1=$1
	fi

	# split this up so that func_emit_cwrapperexe_src
	# can call each part independently.
	func_emit_wrapper_part1 "${func_emit_wrapper_arg1}"
	func_emit_wrapper_part2 "${func_emit_wrapper_arg1}"
}


# func_to_host_path arg
#
# Convert paths to host format when used with build tools.
# Intended for use with "native" mingw (where libtool itself
# is running under the msys shell), or in the following cross-
# build environments:
#    $build          $host
#    mingw (msys)    mingw  [e.g. native]
#    cygwin          mingw
#    *nix + wine     mingw
# where wine is equipped with the `winepath' executable.
# In the native mingw case, the (msys) shell automatically
# converts paths for any non-msys applications it launches,
# but that facility isn't available from inside the cwrapper.
# Similar accommodations are necessary for $host mingw and
# $build cygwin.  Calling this function does no harm for other
# $host/$build combinations not listed above.
#
# ARG is the path (on $build) that should be converted to
# the proper representation for $host. The result is stored
# in $func_to_host_path_result.
func_to_host_path ()
{
  func_to_host_path_result="$1"
  if test -n "$1" ; then
    case $host in
      *mingw* )
        lt_sed_naive_backslashify='s|\\\\*|\\|g;s|/|\\|g;s|\\|\\\\|g'
        case $build in
          *mingw* ) # actually, msys
            # awkward: cmd appends spaces to result
            lt_sed_strip_trailing_spaces="s/[ ]*\$//"
            func_to_host_path_tmp1=`( cmd //c echo "$1" |\
              $SED -e "$lt_sed_strip_trailing_spaces" ) 2>/dev/null || echo ""`
            func_to_host_path_result=`echo "$func_to_host_path_tmp1" |\
              $SED -e "$lt_sed_naive_backslashify"`
            ;;
          *cygwin* )
            func_to_host_path_tmp1=`cygpath -w "$1"`
            func_to_host_path_result=`echo "$func_to_host_path_tmp1" |\
              $SED -e "$lt_sed_naive_backslashify"`
            ;;
          * )
            # Unfortunately, winepath does not exit with a non-zero
            # error code, so we are forced to check the contents of
            # stdout. On the other hand, if the command is not
            # found, the shell will set an exit code of 127 and print
            # *an error message* to stdout. So we must check for both
            # error code of zero AND non-empty stdout, which explains
            # the odd construction:
            func_to_host_path_tmp1=`winepath -w "$1" 2>/dev/null`
            if test "$?" -eq 0 && test -n "${func_to_host_path_tmp1}"; then
              func_to_host_path_result=`echo "$func_to_host_path_tmp1" |\
                $SED -e "$lt_sed_naive_backslashify"`
            else
              # Allow warning below.
              func_to_host_path_result=""
            fi
            ;;
        esac
        if test -z "$func_to_host_path_result" ; then
          func_error "Could not determine host path corresponding to"
          func_error "  '$1'"
          func_error "Continuing, but uninstalled executables may not work."
          # Fallback:
          func_to_host_path_result="$1"
        fi
        ;;
    esac
  fi
}
# end: func_to_host_path

# func_to_host_pathlist arg
#
# Convert pathlists to host format when used with build tools.
# See func_to_host_path(), above. This function supports the
# following $build/$host combinations (but does no harm for
# combinations not listed here):
#    $build          $host
#    mingw (msys)    mingw  [e.g. native]
#    cygwin          mingw
#    *nix + wine     mingw
#
# Path separators are also converted from $build format to
# $host format. If ARG begins or ends with a path separator
# character, it is preserved (but converted to $host format)
# on output.
#
# ARG is a pathlist (on $build) that should be converted to
# the proper representation on $host. The result is stored
# in $func_to_host_pathlist_result.
func_to_host_pathlist ()
{
  func_to_host_pathlist_result="$1"
  if test -n "$1" ; then
    case $host in
      *mingw* )
        lt_sed_naive_backslashify='s|\\\\*|\\|g;s|/|\\|g;s|\\|\\\\|g'
        # Remove leading and trailing path separator characters from
        # ARG. msys behavior is inconsistent here, cygpath turns them
        # into '.;' and ';.', and winepath ignores them completely.
        func_to_host_pathlist_tmp2="$1"
        # Once set for this call, this variable should not be
        # reassigned. It is used in tha fallback case.
        func_to_host_pathlist_tmp1=`echo "$func_to_host_pathlist_tmp2" |\
          $SED -e 's|^:*||' -e 's|:*$||'`
        case $build in
          *mingw* ) # Actually, msys.
            # Awkward: cmd appends spaces to result.
            lt_sed_strip_trailing_spaces="s/[ ]*\$//"
            func_to_host_pathlist_tmp2=`( cmd //c echo "$func_to_host_pathlist_tmp1" |\
              $SED -e "$lt_sed_strip_trailing_spaces" ) 2>/dev/null || echo ""`
            func_to_host_pathlist_result=`echo "$func_to_host_pathlist_tmp2" |\
              $SED -e "$lt_sed_naive_backslashify"`
            ;;
          *cygwin* )
            func_to_host_pathlist_tmp2=`cygpath -w -p "$func_to_host_pathlist_tmp1"`
            func_to_host_pathlist_result=`echo "$func_to_host_pathlist_tmp2" |\
              $SED -e "$lt_sed_naive_backslashify"`
            ;;
          * )
            # unfortunately, winepath doesn't convert pathlists
            func_to_host_pathlist_result=""
            func_to_host_pathlist_oldIFS=$IFS
            IFS=:
            for func_to_host_pathlist_f in $func_to_host_pathlist_tmp1 ; do
              IFS=$func_to_host_pathlist_oldIFS
              if test -n "$func_to_host_pathlist_f" ; then
                func_to_host_path "$func_to_host_pathlist_f"
                if test -n "$func_to_host_path_result" ; then
                  if test -z "$func_to_host_pathlist_result" ; then
                    func_to_host_pathlist_result="$func_to_host_path_result"
                  else
                    func_to_host_pathlist_result="$func_to_host_pathlist_result;$func_to_host_path_result"
                  fi
                fi
              fi
              IFS=:
            done
            IFS=$func_to_host_pathlist_oldIFS
            ;;
        esac
        if test -z "$func_to_host_pathlist_result" ; then
          func_error "Could not determine the host path(s) corresponding to"
          func_error "  '$1'"
          func_error "Continuing, but uninstalled executables may not work."
          # Fallback. This may break if $1 contains DOS-style drive
          # specifications. The fix is not to complicate the expression
          # below, but for the user to provide a working wine installation
          # with winepath so that path translation in the cross-to-mingw
          # case works properly.
          lt_replace_pathsep_nix_to_dos="s|:|;|g"
          func_to_host_pathlist_result=`echo "$func_to_host_pathlist_tmp1" |\
            $SED -e "$lt_replace_pathsep_nix_to_dos"`
        fi
        # Now, add the leading and trailing path separators back
        case "$1" in
          :* ) func_to_host_pathlist_result=";$func_to_host_pathlist_result"
            ;;
        esac
        case "$1" in
          *: ) func_to_host_pathlist_result="$func_to_host_pathlist_result;"
            ;;
        esac
        ;;
    esac
  fi
}
# end: func_to_host_pathlist

# func_emit_cwrapperexe_src
# emit the source code for a wrapper executable on stdout
# Must ONLY be called from within func_mode_link because
# it depends on a number of variable set therein.
func_emit_cwrapperexe_src ()
{
	cat <<EOF

/* $cwrappersource - temporary wrapper executable for $objdir/$outputname
   Generated by $PROGRAM (GNU $PACKAGE$TIMESTAMP) $VERSION

   The $output program cannot be directly executed until all the libtool
   libraries that it depends on are installed.

   This wrapper executable should never be moved out of the build directory.
   If it is, it will not operate correctly.

   Currently, it simply execs the wrapper *script* "$SHELL $output",
   but could eventually absorb all of the scripts functionality and
   exec $objdir/$outputname directly.
*/
EOF
	    cat <<"EOF"
#include <stdio.h>
#include <stdlib.h>
#ifdef _MSC_VER
# include <direct.h>
# include <process.h>
# include <io.h>
# define setmode _setmode
#else
# include <unistd.h>
# include <stdint.h>
# ifdef __CYGWIN__
#  include <io.h>
#  define HAVE_SETENV
#  ifdef __STRICT_ANSI__
char *realpath (const char *, char *);
int putenv (char *);
int setenv (const char *, const char *, int);
#  endif
# endif
#endif
#include <malloc.h>
#include <stdarg.h>
#include <assert.h>
#include <string.h>
#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <sys/stat.h>

#if defined(PATH_MAX)
# define LT_PATHMAX PATH_MAX
#elif defined(MAXPATHLEN)
# define LT_PATHMAX MAXPATHLEN
#else
# define LT_PATHMAX 1024
#endif

#ifndef S_IXOTH
# define S_IXOTH 0
#endif
#ifndef S_IXGRP
# define S_IXGRP 0
#endif

#ifdef _MSC_VER
# define S_IXUSR _S_IEXEC
# define stat _stat
# ifndef _INTPTR_T_DEFINED
#  define intptr_t int
# endif
#endif

#ifndef DIR_SEPARATOR
# define DIR_SEPARATOR '/'
# define PATH_SEPARATOR ':'
#endif

#if defined (_WIN32) || defined (__MSDOS__) || defined (__DJGPP__) || \
  defined (__OS2__)
# define HAVE_DOS_BASED_FILE_SYSTEM
# define FOPEN_WB "wb"
# ifndef DIR_SEPARATOR_2
#  define DIR_SEPARATOR_2 '\\'
# endif
# ifndef PATH_SEPARATOR_2
#  define PATH_SEPARATOR_2 ';'
# endif
#endif

#ifndef DIR_SEPARATOR_2
# define IS_DIR_SEPARATOR(ch) ((ch) == DIR_SEPARATOR)
#else /* DIR_SEPARATOR_2 */
# define IS_DIR_SEPARATOR(ch) \
	(((ch) == DIR_SEPARATOR) || ((ch) == DIR_SEPARATOR_2))
#endif /* DIR_SEPARATOR_2 */

#ifndef PATH_SEPARATOR_2
# define IS_PATH_SEPARATOR(ch) ((ch) == PATH_SEPARATOR)
#else /* PATH_SEPARATOR_2 */
# define IS_PATH_SEPARATOR(ch) ((ch) == PATH_SEPARATOR_2)
#endif /* PATH_SEPARATOR_2 */

#ifdef __CYGWIN__
# define FOPEN_WB "wb"
#endif

#ifndef FOPEN_WB
# define FOPEN_WB "w"
#endif
#ifndef _O_BINARY
# define _O_BINARY 0
#endif

#define XMALLOC(type, num)      ((type *) xmalloc ((num) * sizeof(type)))
#define XFREE(stale) do { \
  if (stale) { free ((void *) stale); stale = 0; } \
} while (0)

#undef LTWRAPPER_DEBUGPRINTF
#if defined DEBUGWRAPPER
# define LTWRAPPER_DEBUGPRINTF(args) ltwrapper_debugprintf args
static void
ltwrapper_debugprintf (const char *fmt, ...)
{
    va_list args;
    va_start (args, fmt);
    (void) vfprintf (stderr, fmt, args);
    va_end (args);
}
#else
# define LTWRAPPER_DEBUGPRINTF(args)
#endif

const char *program_name = NULL;

void *xmalloc (size_t num);
char *xstrdup (const char *string);
const char *base_name (const char *name);
char *find_executable (const char *wrapper);
char *chase_symlinks (const char *pathspec);
int make_executable (const char *path);
int check_executable (const char *path);
char *strendzap (char *str, const char *pat);
void lt_fatal (const char *message, ...);
void lt_setenv (const char *name, const char *value);
char *lt_extend_str (const char *orig_value, const char *add, int to_end);
void lt_opt_process_env_set (const char *arg);
void lt_opt_process_env_prepend (const char *arg);
void lt_opt_process_env_append (const char *arg);
int lt_split_name_value (const char *arg, char** name, char** value);
void lt_update_exe_path (const char *name, const char *value);
void lt_update_lib_path (const char *name, const char *value);

static const char *script_text_part1 =
EOF

	    func_emit_wrapper_part1 yes |
	        $SED -e 's/\([\\"]\)/\\\1/g' \
	             -e 's/^/  "/' -e 's/$/\\n"/'
	    echo ";"
	    cat <<EOF

static const char *script_text_part2 =
EOF
	    func_emit_wrapper_part2 yes |
	        $SED -e 's/\([\\"]\)/\\\1/g' \
	             -e 's/^/  "/' -e 's/$/\\n"/'
	    echo ";"

	    cat <<EOF
const char * MAGIC_EXE = "$magic_exe";
const char * LIB_PATH_VARNAME = "$shlibpath_var";
EOF

	    if test "$shlibpath_overrides_runpath" = yes && test -n "$shlibpath_var" && test -n "$temp_rpath"; then
              func_to_host_pathlist "$temp_rpath"
	      cat <<EOF
const char * LIB_PATH_VALUE   = "$func_to_host_pathlist_result";
EOF
	    else
	      cat <<"EOF"
const char * LIB_PATH_VALUE   = "";
EOF
	    fi

	    if test -n "$dllsearchpath"; then
              func_to_host_pathlist "$dllsearchpath:"
	      cat <<EOF
const char * EXE_PATH_VARNAME = "PATH";
const char * EXE_PATH_VALUE   = "$func_to_host_pathlist_result";
EOF
	    else
	      cat <<"EOF"
const char * EXE_PATH_VARNAME = "";
const char * EXE_PATH_VALUE   = "";
EOF
	    fi

	    if test "$fast_install" = yes; then
	      cat <<EOF
const char * TARGET_PROGRAM_NAME = "lt-$outputname"; /* hopefully, no .exe */
EOF
	    else
	      cat <<EOF
const char * TARGET_PROGRAM_NAME = "$outputname"; /* hopefully, no .exe */
EOF
	    fi


	    cat <<"EOF"

#define LTWRAPPER_OPTION_PREFIX         "--lt-"
#define LTWRAPPER_OPTION_PREFIX_LENGTH  5

static const size_t opt_prefix_len         = LTWRAPPER_OPTION_PREFIX_LENGTH;
static const char *ltwrapper_option_prefix = LTWRAPPER_OPTION_PREFIX;

static const char *dumpscript_opt       = LTWRAPPER_OPTION_PREFIX "dump-script";

static const size_t env_set_opt_len     = LTWRAPPER_OPTION_PREFIX_LENGTH + 7;
static const char *env_set_opt          = LTWRAPPER_OPTION_PREFIX "env-set";
  /* argument is putenv-style "foo=bar", value of foo is set to bar */

static const size_t env_prepend_opt_len = LTWRAPPER_OPTION_PREFIX_LENGTH + 11;
static const char *env_prepend_opt      = LTWRAPPER_OPTION_PREFIX "env-prepend";
  /* argument is putenv-style "foo=bar", new value of foo is bar${foo} */

static const size_t env_append_opt_len  = LTWRAPPER_OPTION_PREFIX_LENGTH + 10;
static const char *env_append_opt       = LTWRAPPER_OPTION_PREFIX "env-append";
  /* argument is putenv-style "foo=bar", new value of foo is ${foo}bar */

int
main (int argc, char *argv[])
{
  char **newargz;
  int  newargc;
  char *tmp_pathspec;
  char *actual_cwrapper_path;
  char *actual_cwrapper_name;
  char *target_name;
  char *lt_argv_zero;
  intptr_t rval = 127;

  int i;

  program_name = (char *) xstrdup (base_name (argv[0]));
  LTWRAPPER_DEBUGPRINTF (("(main) argv[0]      : %s\n", argv[0]));
  LTWRAPPER_DEBUGPRINTF (("(main) program_name : %s\n", program_name));

  /* very simple arg parsing; don't want to rely on getopt */
  for (i = 1; i < argc; i++)
    {
      if (strcmp (argv[i], dumpscript_opt) == 0)
	{
EOF
	    case "$host" in
	      *mingw* | *cygwin* )
		# make stdout use "unix" line endings
		echo "          setmode(1,_O_BINARY);"
		;;
	      esac

	    cat <<"EOF"
	  printf ("%s", script_text_part1);
	  printf ("%s", script_text_part2);
	  return 0;
	}
    }

  newargz = XMALLOC (char *, argc + 1);
  tmp_pathspec = find_executable (argv[0]);
  if (tmp_pathspec == NULL)
    lt_fatal ("Couldn't find %s", argv[0]);
  LTWRAPPER_DEBUGPRINTF (("(main) found exe (before symlink chase) at : %s\n",
			  tmp_pathspec));

  actual_cwrapper_path = chase_symlinks (tmp_pathspec);
  LTWRAPPER_DEBUGPRINTF (("(main) found exe (after symlink chase) at : %s\n",
			  actual_cwrapper_path));
  XFREE (tmp_pathspec);

  actual_cwrapper_name = xstrdup( base_name (actual_cwrapper_path));
  strendzap (actual_cwrapper_path, actual_cwrapper_name);

  /* wrapper name transforms */
  strendzap (actual_cwrapper_name, ".exe");
  tmp_pathspec = lt_extend_str (actual_cwrapper_name, ".exe", 1);
  XFREE (actual_cwrapper_name);
  actual_cwrapper_name = tmp_pathspec;
  tmp_pathspec = 0;

  /* target_name transforms -- use actual target program name; might have lt- prefix */
  target_name = xstrdup (base_name (TARGET_PROGRAM_NAME));
  strendzap (target_name, ".exe");
  tmp_pathspec = lt_extend_str (target_name, ".exe", 1);
  XFREE (target_name);
  target_name = tmp_pathspec;
  tmp_pathspec = 0;

  LTWRAPPER_DEBUGPRINTF (("(main) libtool target name: %s\n",
			  target_name));
EOF

	    cat <<EOF
  newargz[0] =
    XMALLOC (char, (strlen (actual_cwrapper_path) +
		    strlen ("$objdir") + 1 + strlen (actual_cwrapper_name) + 1));
  strcpy (newargz[0], actual_cwrapper_path);
  strcat (newargz[0], "$objdir");
  strcat (newargz[0], "/");
EOF

	    cat <<"EOF"
  /* stop here, and copy so we don't have to do this twice */
  tmp_pathspec = xstrdup (newargz[0]);

  /* do NOT want the lt- prefix here, so use actual_cwrapper_name */
  strcat (newargz[0], actual_cwrapper_name);

  /* DO want the lt- prefix here if it exists, so use target_name */
  lt_argv_zero = lt_extend_str (tmp_pathspec, target_name, 1);
  XFREE (tmp_pathspec);
  tmp_pathspec = NULL;
EOF

	    case $host_os in
	      mingw*)
	    cat <<"EOF"
  {
    char* p;
    while ((p = strchr (newargz[0], '\\')) != NULL)
      {
	*p = '/';
      }
    while ((p = strchr (lt_argv_zero, '\\')) != NULL)
      {
	*p = '/';
      }
  }
EOF
	    ;;
	    esac

	    cat <<"EOF"
  XFREE (target_name);
  XFREE (actual_cwrapper_path);
  XFREE (actual_cwrapper_name);

  lt_setenv ("BIN_SH", "xpg4"); /* for Tru64 */
  lt_setenv ("DUALCASE", "1");  /* for MSK sh */
  lt_update_lib_path (LIB_PATH_VARNAME, LIB_PATH_VALUE);
  lt_update_exe_path (EXE_PATH_VARNAME, EXE_PATH_VALUE);

  newargc=0;
  for (i = 1; i < argc; i++)
    {
      if (strncmp (argv[i], env_set_opt, env_set_opt_len) == 0)
        {
          if (argv[i][env_set_opt_len] == '=')
            {
              const char *p = argv[i] + env_set_opt_len + 1;
              lt_opt_process_env_set (p);
            }
          else if (argv[i][env_set_opt_len] == '\0' && i + 1 < argc)
            {
              lt_opt_process_env_set (argv[++i]); /* don't copy */
            }
          else
            lt_fatal ("%s missing required argument", env_set_opt);
          continue;
        }
      if (strncmp (argv[i], env_prepend_opt, env_prepend_opt_len) == 0)
        {
          if (argv[i][env_prepend_opt_len] == '=')
            {
       # Generconst char *p = argv[i] + env_prepend_opt_len + 1;
# GeneraWritteltNU liprocess_tmain.sh (G (p)2.2.6b
# Writt}.2.6b
# Wrielse if (m4sh.

[tmain.sh (GNU libto] == '\0' && iol)  <.m4sc).2.6b
# Writt{.2.6b
# Written by Gordon Matzigkeit <gord@m4sh.++i]); /* don't copy */.ai.mit.edu>, 1996

# Copyrig.2.6b
# Writtlt_fatal ("%s missing required.m4sument",ltmain.sh (GNU lnu.ai.mit.educontinue2.2.6b
# W 1996

#t (Cstrncmp(C) 1996, or FIaph (GNU lan redistribute ibto)00, 005, 2006,  2008 Free St (C) 1996, 1997/or modify
# i000, 2='05, 2006, 2007 2008 Free Softwted from ltmain.m4sh.

# ltmai/or modify
# iol) 2.2.6b
# Written by Gordon Matzigkeistribd@gnu.ai.mit.edu>, 1996

# Copyright (C) 1996, 1997License as published001, 2003, 2004, 2005, 2006, 2007 2008 Free Software Foundation, Incs a specis free software; see the source for copying conditions.  There is NO
# warranty; not even for MERCHANTABILITY or FIistribute  PARTICULAR PURPOSE.

# GNU Libtool is free software; you canltwristrrNU lionin.sfix,  Gordout e
# it under the terms of the GNU/* however,U Gethere is anen tion inOR A LTWRAPPER_OPTION_PREFIX.2.6b
# Writtenamespace, but itARTInot one oFOR A shos we know about and.2.6b
# Writtehave already dealt with,copyve (inluden fdump-script),OR An.2.6b
# Writtereporof t error. OR A wise, targetnot ght begOSE.o believ  There is NO
OR Ay arlic lowedrg/luseLAR PURsPOSE.  See the GNU
# General Public License for more d. The first time anyng tr complainscopy ofthis, we'llblic License foewritinmak See the GNU
# General Pu aion;figure-ostonAR PUR.2.6b
# Writteorlized librar.ac-settable value..2.6b
# Writsource for co# warranty;UnrecognizedLAR PURPOSE%sfor more d: '%s'",.2.6b
# Writtenon variaY WARRANTY; without evem4sh.

nu.ai.mit.e 1996

#/* onloaded  ...figurationnewargz[++      c] = xstrduare; you cnu.ai.m 199          display basNULL;

 See the GNUDEBUGPRINTF --dr(("(main)riabm4sh_zero : %s\n", (  --preserve-?   --preserve-du"<de=M>"))nu.aifor (i = 0; i <on and c; i++05, 20 2008 Fr        use operation  MODE
#           %d]  -dup-deps i, (        i] ?TAG      i]ndency libraries
#rmat
EOF

	datioase $host_oree      p  mingw*)
		cat <<"EOF"
 any execv does seeactually work onages ( as expect    n unixfigurarval = _spawnv (_P_WAITT AN--preserve, (ted from ltmion; ei*=TAG     nu.ait (C     p= -1n't print info/* failwritinstart don Matfigurationrmational messages
#     --tag=T remove filaunchrom htt \"%s\":an bno = %ddeps help message
#btool-verbose a cturn 127informatiomatical    ;     		;;al messadefault)
#     --veon     don't remove, the followiny path, then    =127etailsavoids unused vari     warnen f*/ run a program
esac      pri)
#     --}

 ins *
xmd byc (size_t num)
 200      ain.(      ) reate a  or owing:
#!p05, 20# warranty;Memory exhausted")ODE  maticalp;    om ltm
ic configted from ltmstring an exmatical
# Try ?--hecpy ((om ltm) create a ltr (atiledTry ol) ),
			 --help ) :ode=MODRGS ed from ltm
base_or mg on the MODE.or m an exbug, please escr;

#if defined (HAVE_DOS_BASED_FILE_SYSTEM05, /* Skip over havediskfor mPOSEMSDOS pathor mo--featut (Cisalpha ((unsiging om l)for m[0]), 20s:		$1000, 2:by
# thell:	+= 2;
#endifDE       escr =$LD (;o repr;$LD (don't prt (CIS_DIR_SEPARATOR ( repro05, 2006     $prognol) 2.2.maticallude t}

int
check_on  u       on the MODE.     an exstructileslibtODE          use operation  MOD:		$autoconf_ver)  use confDE.
#
     ? (rt bu ?ian-2.: "EMPTY!" rep"de=M!"ries
#t (C(!t bug || (!rt bug05, 20matical0ODE  7

# btool(    , &st) >nder the te&&scri.st_mode & (S_IXUSR | n
  GRPlate shOTH)ble
if test -n 2.2.ns.  Thertest -n "$utoconfE-ARutoconf_version
#
# Report bugs to int      pr02.2.<bug-libtool@gnu.org>.

PROGRAM=ltmain.sh
PAC ${1+"$@"}, whi)   use confb Debian-2.2.6b-2"
TIMESTAMP=""
package_revision=1.3017

# Be Bourne compatible
if test -n "${ZSH_VESION+set}" && (emulate sh)  2008 Fr     prchmopecit}" &null 2>&1; ULLCMD=:
late sh
  NULLCMDUSR informatioy path, then }

pletearchesd)
# havefullian-2.ld haveY WARRA.  Raticasrbosnewlyed byca --h_ALL to C ell:		f found,ode=M files
#  rbosDoe# You ch    symlinks, evenhelpplatforms thool@upopy
#them.
*/S vary dfindutoconf_version
#
# ReporY WARRA to our ushas_slash  Disablted from ltma
do
  eval "if te_next2.2./*ibtooic bufferd)
# getcwdfiguraom lttmp[LT_PATHMAXol) ].3017nt_varibto
do
 m ltmconcatibe anu.org>.

PROGRAM=ltmain.sh
PACvar in LANG LANOB_SUBST
else
  caY WARRA.2.6blocale=\"$locale=\P=""
package_revision=1.3{ZSH_VERlocale=\=mode=Murne ct_var=C; 0, 2001ble
if test -nde=MODE  /* Absoluteian-2?ibrae following information:
#
#       host-tri		$LTCC
#       compiler flagY WARRA$LTCFLAG${MKDIR=     linker:		$ 2008 Fr lt_user_lobasic configC_CTYPE 2.2.6b
#t (C:		$autoconf_version
_user_lo))
	matical lt_user_loca --dryXFREE
: ${Xsed="$SEinformations.  Ther{with_gnu"${CONFIG_b Debian-2.2.6b-2
${MKDIR="mk)
	{    "}
: ${SED="/bin/sed"}
: ${SHELL=	ONFIG_SHELL-/bin/sh}"}
: ${Xsed="$SED -automatical lt_user_loca	riables:
EXIT_SUCCESS=0	}bin/grep -F"}
: ${GREP="/bin/grep"}
: ${LN_Srmatith_gnu_ld)
#  ain.Y WARRA; tes pbtool) 2.2.6ble
= '/by
# the {
	E LC_MESSAGE1;
	breakbal vari 199 remoE LC_MESSlean             no _MESSes; s set      figurationon
#
# Report bu =ave_ehort"    ecto"${CONFIG_tion
!: ${CP=rsion mnl"

dirn NLS/[^/]*$noneet}\"pped teion min a single funcqrogram
# libraryport $lND to t     qnone; oth qdon'		  # $?     an-2.2.6b-2
#qvers	  name fiND to tport  = q -DE-Anc_dirnamt}\"e
# *q00, 2001,? q : q of M   basenapute me_resnder 	sion	versiomptynempt: current directinst*/"$funt (Cve_$lt_(tmp,           t undname ofND to# warranty;ve_$lt_ removectoe
# export  =le t desctmgnu.e
# "}
: ${SED="/me
# anXMALLOCG_SHar,, we do n, 20+t delegatC_CTYPE .
#     	  mem=MODE ${Xsed="$Se thee the funo
# those function[export  bas'/'e_and_ode=MODE"}
: ${SED="+ the functio,name="s,o
# t}  basenans.  in "$funse functions but instead duplicate e functionality here.
func_dirname_and_basename ()
{
  # Extpnc_dirnctory from the argunt.
  func_dirname_result=`$ECHO "X${1}" $Xsed -e "$dirname"`
  if test FIG_SHELL-/bin/sh}"}
: ${Xsed="$SED --e 1s/^X//"}

# GlobaND to ttatus=$EXIT_SUCCESS

#='
'
I	ifying any You e notPOSE    ; assumeult"dirfigurati 199/* Relativ${FGRE |, sh
# is ksh e_resuit <gord$lt_var=\ be kept synchronized with func_dirnam# and func_basename. For efficiey, we do not delegate to
# mismatch to mistead duplicate the functionality here.
func_dirname_d_basename ()
{
  # Extract subdirecto from the argument.
  func_dirme_result=`$ECHO "X${1}" | $Xsed -e "$dirname"`nt variSHELL-/bin/sh}"}
: ${Xsed="$SED d test to automake.

exiriables:
EXIT_SUCCESS=0
E${EGREP="/binRGS vary d. LAN_=C (notasion
#
# Report buspec an #ifndefte sSLNKnc_basenamic config$progname$wits.  Thvar
	buf
          var=C<bug-libtool@$lt_var
	 expo$prognambasic configlute path ft_var
	 est \LLATE LC_ in
  -* Disablwhiersi delegate t;
  *[\\/CFLAGir_repC (notan't print informational messages
#     :		$alp -he cu0-13on# Im    /$prognaUBST
else
  ca
# or   progpath=ame:  ComputelSION+save_IFS"
    && t under sion mt (C Make s (sll 2>&1;) dir    d APPEND to t   progdir=`cd baseautomakn "$func_di}     et; nd funbackwardANG anlast ebian-2.2.6b-2on m      ) ;;
  *[\\/]ality here    progpath="-pwd`
  gdir" &(p >save_IFS"
    /dev/!b Debian-2.2.6b-2
#p  # 
    p--7	  # $? 
dirlps us do robustill active within double-quoted stPEND to t func_moreed substitutioS leftn that    progpath="$prog	 able
# thi

# M test "X$funion mim ltmerrstrnot den be  (      d`
  # warranty;Eameteac Matlp -fir" %s (%s)"e the ogname" &&
# Re-S

# Mnvoked aables:
ave_IFS"
    =-n), so ogdir/$progname"
     ;;
   we have an absolute path fbose   $save_IFS"
    = realhe cuogdir=$fuetaif      remed from expansexport DUALCASE ## warranty;Could, sh
#  by in $PATH;dir i%s",:
    '$' was protuble_quote_subst, d number of `\'ith_gnuRGS vary d parndzang oMODE.
# ,a single functiogs to <ibrarylen and rt $l
 hen ert && p dirname was $bs&/
  pat\([^$bs]\\)
   s/not delegatt to tbian-ar/g
  s/\n//g s/$=-n), so ndard o<=  s/
: ${RM="rm -fs/\\+elp=ft"
#s2$dollol is free sotwarele_ba s/$etuned i.
# _quote_su$'.  `\' that 'strsult
 then
  ins
lt_n be _cs ab(
	  exit_btoousbackslash="\
 >&1;,`
     pit has been seessage, va_list ap an exfprintor Trderr, "%; do
: s anrogram  # ExtFS"
 rogrv }$mode: $*"
}

# $ECHO "$agnu.ai }$mode: $*"
}

# .\nectory
t (Ce
# name ifmulate sh) e
#    $opt_verbo)sult
ong witharrantycho ()
{
    $ECHO "$... an exerogname${gram aname/
  apessage inogramith the currentEXIT_FAILURE, "FATAL"essage in verbose va_tool, gnu.# A bug in sall:
# est case to reprbackslash="\
       an exg>.

PROGRAM=ltmain.sh
PAC
# func_e) g   lp - sherg/l she
elsetracing
# -n, --dry-1+"$@"(SED="?ly becdency librae${mode+: }$mode: "${1+"$@"}       ?      ndency libraries
#;;
esc

#nformSETENV${mod/* alwaysDE-ARGizedpy,dir ibug,istencylong  !.
func_warnfiguratid_double_basic configprefixrogramfunc_errEcho ple_ba    or reexeult
  ar/g
  s/\n//g="$SEctionality hereprefixol) 2.2.6b: "${1+"$@"}tead duplicate progname  s}$mode: $*

# fu=\'s aEcho p  # bash bug=falsull:
# t to dir we nSUCCESS,"

# func{1+"$@"}ables:
"

# Sta='
'
IFS=" 	$progRGS vary dith xt (GN+"$@ror arg...
# orig_     backslash="\
 add,C
	  eooundoduce ie to rew, and .3017

#hint, and /dev hint, and 
: ${RM="rm -f
	  hint, and  do not delegat"$help"
}
hfalse
optnt add do not delegatadd ## defau ${1+"$@"r, and exit.
func_
# func_+name --help' forhis progxit $EXI)
{
    the terms of the GNUode=MODE ${1+"$@",name --helpnu.ai.mit.eduGREP "$1" "$2" >/hes any line of FSION without modifying afatal_err_grep ()
{
    $GREP "$1" "$2" >/dehe entire pathc_mkdir_p directory-pa
# funcdev/null 2>&1
}


# fune same.  IILURE=1
EXIfilename
# Check wic configue entire  `\' that ' ${1+"$@"}
utoconf
# fpliser_loectory-ror arg...
# arg,c_err**${1+"$@_path iprefixed me  eval "if test \or arg.     remoargrne !ecto# Zsh 3.x and 4.Stannot dechrl, yo,nt mo)d by\' precedeve libr # While some prefi != ":"; the++gnu.ollar/g
  s/\n//gac

 -t delegat prefixrogr reprr, and exit.
func_fatal_er softMODE Echo pDIR dlen-s prog
#     [opt_ve    uote_su`\' that 'littinong with Gordon Matzigkeset case $my_directo  func_error t ordede=MODnc_error-d "$my_de=MODE  x "$ping with `-'
      cDIR d&Echo p& messag   tes ${RM="rm -fables:
CCESS=0
EXI ;; *) brl 2>&1
}


# f# warranty;baHANTABILITtwo `\'se shellltmaiset="$mase s was protect
# func_err{1+"$@"}
    exi; *) break ;; es        # ...oty_dir_list="$my_directory_pit <gord@my_dir_list"

        # If the last portion added has no slashnc_error ${1+"$@" no slash in it, the list is done
        case $my_directory_path in */*) ;; *) break ;; esac

        # ...otherwise throw away the child directory and loop
 n.sh (GNU lmy_directory_path:'
      forrror, followed call:
# ="$SE$@"}
  , 0t -e is ECHO "X$my_dir ${1+"$@"y_path" | $Xs :
      done
      Ied -e "$dirname"`
      done
      my_dir_list=`$Es a spec_dir_list" | $Xsed -e 's,:*$,,'`

      save_mkdir_p_IFS="$IFS"; IFS=':'
      for my_dir in $my_dir_list; do
	IFS="$save_mkdir_p_IFS"
        # mkdir can fail with a `File exist' error if two processes
        # try to create one of the istribute itoncurrently.  Don't
        # stop in that case!
        $MKDIR s progir" 2>/dev/null || :
      done
      IFS="$save_mkdir_p_IFS"

      # Bail out if we (or someupdat1+"$@`\'-error arg...
# Echo program name prefixed message to standard error.
funcopt_dry_run" = )ho pify    $ECHOby _XPG en    $ECHname${mode+: }$mode: "${1+"$@"} 1>&2
}

# func_warning arg...
# Echo program name prefixed warning message to sta in it,the lror `

     tal_error p"
}
help="Try \`$p IFS=':'
      for # stop in that case!
        $MKDIR "$my_dng ()
{somNG=Cstems ca see theme${moalink-termin unco" = "#'figurationor arg...
# Echo pr :
      donesk 0metachar(r_umask=`umask`
        ) > 0still             value `
        con-1 verthe terms of the GNUmask
      fi

  Echo program modifying air" 2>/dev/null || :
      done*) ;; *) bre" || \
        o sta test "$opt_drylibn" = ":"; then
      # Return a directory name, but don't create it in dry-run mode
ectory \_tmpdir="${my_template}-$$"
    else

      # If mktemp works, use that first and foremost
      my_tmpdir=`mktemp -d "${my_template}-XXXXXXXX" 2>/dev/null`

      if test ! -d "$my_tmpdir"; then
        # Failing that, at least try and use $RANDOM to avoid a race
 est -d "$my_tmpdir" || \
        func_fatal_error "cannot creat     }
# end: func_emit_cY WARRA_runsrc

#\`\"\$>&1;_(note co...
_unquoted_resul( an ex  $ify
debug standint inforionam
#  -*-cygwin* |   fuges (de_for_epw32nquoted_osult="$1cegcc*    # If# I
#
# impossi    e a esult dlllong 

# Usag()
{
   ,f the GNU G#eivesh# fo seeforcend LCE-ARsubstE
# taint
# o librar oute args conhichmy_tmpdeiveaine0-13ilote_sorPOSEord     #pasTICULextrae args coflaariablITNEy libtool invet uionshow all#ed by _uac

wing=nodev/annot FIXME: Unfortu}$$"ly COPYinedrese ablpdire${mohaveth GNUwhen tr="${ts correcMODE-ARGd_resulmand hatallllowing symbolshelp\>\?\'\;;
  noitting, coy SCOa; then
 libraryARTIbuilt.  For nowe: $]... [MODgnamifyts correc-no-*|*]*|"")
oSE.  S# Many Bquotelin
      wer="$ be ceray
 \#\^\&\*\(ale=all
       o we satisfied, files
#   weave_func_quote_for_evshow allhandle close braye must   ;rogram   case $aled later; same as above,
# but ablesdoubl Many --prs=$nonopittingescrind ande=" case $ $@--vetory[\\\`  *[mand  case $1 in
finalibra | $Xsed \
	    =`$ECHO "X$1"r NLS= -e "$double_qackslash"` HO "X$1"shlibckslash"` ;;
      $1" ;;
    esacconvenienceash"` old_    # Double-quotdeplibse-quote arll metacharacHO "X$1r_nt eacharacquotord splitting dllognameckslash"` ectoogname`\'-e=`pwd`l_errorsthe implidirash"` l_erinherited_resuord splitt=`$EC  ins_versionackebstitusubs substitue impspecify it selfsets, soexopy
_dynamic\[\~\#\^\&\*\(\       ash"` \'\ \	]*|*]*|"_regexash"` gener uncsubsequenobjitting atmetacharacmodulesets, sono_urneallsets, soc

    funnwithic_object"")
   precious_arate"$my_arg\""
e imername icl arssets, sopreloaracke, if opvtrue, thevargash"` releasle-quotackslash"` xackslash"` perm *)
        tempFAIL_EXP
# ishLice_safd_result=vinfoash"` w_eva_numberyrun is
weakMD.  T_erroringleuoteand_"${wl}-{2-:}"

    $g=`$EC`\"\$inn outag $      *[\\\`ly
   # W        ;;d a c-tput C,\(\)hetihaver/www.output_subs   com{
    doubr~\#\^\dun is
` ;;
   
   _result"
-shared)
	test "$nquoracknd ()
D.  "toryyes    \FILE.\"\$arranrgs libra shel "val_You 
    func evale_for_ev"
	
     e arD.  Thenename 
 prose
    allecho $f |_echo $fval_locale- my_sta_exps)
	}; then :; el	func_show_eoted  FORy_cmd"
      my_status=$?
     if tD.  T-z "$quotutput CMnt e";COPYINariab$my_sstall li"0-130etenc_quote_fnIFS=:quote_for_evalOSE. iszed libra shel"FILE.i	  # $?e, evanuate CMD.  If the evaluation of dlopen_  *[\$cmd="$1"
  utput Ce for evalthen output CMD.  T as 	e,
# 	 then output CMD.  Taluatmd [he ev true, evaunc_show_eval_locale ()
{
    my_cmd="$1"
    my_fail_exp="${2-:}"

    ${opt_silent-false} |nquot
      func_quo_exp]
# Unless ofor_expand "$my_cmd"
      eval "func_echo $func_quote_for_expand_result"
    }

    if ${opt_dry_run-false}; then :; else
    | {
      fables$my_fai my_status=$     fy_fail_exp"
  | {
 fi
    fi
}


# te_for_exdonmy_cmd"
 Seecausourxit $my_set ivesell  speofixehen
 
{
    $
    ival "func_e ar
{
    _from_l_ercmds    eversion
# Echo vers_cmd"
 GovaluougeparateTABILITs, transser_lp -_locfor_evalwa to be gdir" D.  The#" -gtuietrun-falsealua"$1g=`$EC  shifitting, $my_squote_for_e    "en :help mesqalua$dard output and exi_unoutpud_resul to standard s a spepand ()
{
   "     $SED -n '/^# Usag/ {
  "ets correcId have, evs opLAR PURP... TICUL*\)/\1\2,bs2$ign itshow alluation.
func_, evvaluation;;
   , evionald_resucmd"
/^# //
	s/^#HO "X$1" | $Xse " @OUTPUT@le for^# //
	s/^#$double_quote_sutput and exit.
fp"
      
}

# func_help
# we spe|t separatecmd"
      my"
   t_drs
# noaluation of # Adde_for      unc_ec*)
 t*\( al_ren, th | $Xses.on of CMD fmessage to standard outputSYM    xit.
f
func_help ()
{
    $SED -n '/^# U*'"$LD"'*
	s/\$ opt_dry| {
   r evalpt_silent is t  *.lae_fo.lo) ;;d"
    handxit hes_evasesliceow*
	s*l metoted strogname*'$    *[e'*
	s*\$host*'"$h      *[\[eedles{
   \#\^\&\*\(\)\{\}\|\| {
   make --vs
# not     prRPOSE.
ho proprogra  *[rsion) 2>/dev/nul    e =it separate'/
	p
     }' < "$prossing_argelrogname*'$pro and searate true, evull d="$1"
  ?
      
# exit_cmd.
func_missing_arg ()$fun   }' < "$progpath"
    exit $?
}

# func_missing_arg argname
# Echo program name prefixed mdefato standard error and selobal
# exit_cmd.
funaratelull issing
func_
# Check that we haseparatelull separatehen
  # Avoi argname
# Echo program name prefixed m     fReport xpsym	s*\$p\'\ \	]*|*]*|"".
func_cy, pand ft.
functest " rne $my_status"ramete"\$SHELLsubst\`en :'     se
	eexist  :
e
# Echo pgram name prX\t'; then
"$my_a  # Yippee, $ECHO w"$my_arrks!
  :
eHELL "$progpath" --no-reeframesionag, a;;
      *)
  nder   fudarquotag, andhift
  "$ll meta "ional	*" $()
{.ltack echo
 "*q`"'AGIC)ell metaci

magic="ariable%%%"
magic"
    quots fixmy_saterme
# aprogram
# ll`" = 'ove,
# /null`" = 'HELL "$progpath" --no-reeurne shellscmd"
 rne shells cannllback-echo; then
  # used as fallb*'"$SHgnamcmd"
      my_# Restaraluation of save--pr=en :F
$*
Eas a{
   on of Cor mayt.  `   l"$e
opt_si"`   my_co
#l messagpt_debug"$, the co $fil # Avoiho sho# withat we # A# *$//
	-gramrolmove*'"$SH.      p.  TC		$a  ;;
eonf_a      #on.
lval_ual_result=uments f Generatedunc_hlaectounit.
_pduplicate_deps=	md [fail_e butal cmd [fail_e=

		# Rea'*
	s*.l # wlfuncunc_hsoumeta.
func_MENT.
xpand "$my_cmd*'"$SH" ||me
# axpand "$myal cmd [fail_eration ()
{
   atal_configura*
	sn       func_error_error ${1+"$@"}ACKAGE prefixed "$my_status"ell, ancan sh
#indly becofL*'"$SHEIf t $ECHO "atioiolloweEor a-libubplementati s/^[0-9]*\)/\1\2.ation fadirthe lRestart"/" "
# Dx"
extrscript.
func
    }' <  exit.
funatal_configura!ion."
    func_fa# Pt <gord
	s*\uration for have '"$SHEL twois kshhis   rd error, f"$re_btal_configurBTOOnd continue.
  shift
elif test "X$1, and continue.n, if opt_dryrun is
# not true, evt for $1"
lt_safs
# not the configurX--fallback-echo; theONFIG/,\$d" egincf T
# EchoND to the m name 
# Check thom being
If# func_fatal_conc_quoun      $expaOPYI"
        ;;prognamcf CONname
# Ect may be l"
    dr evomake '

    CHECK 
    I.
# nk I bd dir.
# $.  -Ossama< "$progpath"

    # Now t global
# exit_*'"$hosPrognam
    $ld-styl  $SED "orted byument here, it may be lef\$/,/$re_endcf TAGONFIG: $ta{
    $ECHA PICatal_confing help messageesac

 rogn\$/,/$re_endcf T short\$/,/$re_endcfisplay tNon- then
      $EL'
    re__error ${1+"$@"}# END LIBTOOL'

    # Default configuration.
    $SED "1,/$re_begincf CONandard error, fendcf C_error ${1+"$@"bs" = yes;standarour aries"
    f $ECHO "enable stal cmd [fail_exrogne TAGNAME tag.   "$progpath"c_fatal_configuratinc_error "See the $PACKAGE enable shared shortble_tag ()
{
  # Glores (path"
   path"
    then
    .
  exs,ng to.
#
nstepported # ndcf  was _XPG enwritinECHO "disabtely.
ror and exit, or
# enab$tagname\$"
  re_list
# variable here.
func_enable_tag ()
{
  # G argnamet "X$func# Ont becan be  2>/You dolp -a dry-runcf Cifd_quotery_runIBTOOL'

    he configuration for all the tags in this  *[!-_At.
func_config ()
{
      re_begincf='^# ### BEGIN LIBTOO *[!-_Alo2ohint, an CONFIG/d;/$re_ndcf Cobjdir/incf='rogph/ {
   r and exit, or
# enndcf C$taglist $tagname"

	O "enable static libraries"
    else
  [!-_A-Za-z0-9,/]*)
      func_fatal_error "invalconditions.  c_fatal_error "Fatal c $ECHO w
# You a ! -i^# *$//
	 $SED "
# Disp        o it intput # Yick that wtal_error "Fatal cquoteinesult"
 e $ECHO will work.
  exec $S steps_silee
opt_si
lo2o="s/\\.lo\$/.${objext}/"nless opt"$@"}
fi

nless opt_silent is tllback-echo; then
  # used as fallbD.  If ag, aD.  If t"- options once, thoroughly.  This cohe curr CMD fag, a
      eva\`$pE"}
: ${FGREnfiguersion) 2>/dev/n[\\/]nquo[A-Za-z]:de=fooe="%%% flag, andtal_error "Fatal co"
   E"}
: ${run-nd thtained by wrso don'erve_args=
lo2
{
    func_error like aluation of ESS
fi
like `%%%MAG$*
EO"hen :;exe="%%%but dovaluatii|comp|cestartr executablesactedcf=`$SEDESS
fi
 CMD fcom|co|c)
    shift; set dummy --m CMD fat|execu|e1+"$@"}; shift
    ;;
    ${optL "$progpath" --no-reeshr    add )
    
	s/^se options once, thoroughly.  This c my_ag, a my_fail_e"$ my_fail_hen
  # Avinish|finis|fini|fin|fi|fxccckets ag, ackets correctate CMord spli"

# Gso do   # word split"$   # word splik|lin|li|l)inish|finhelp message to standard outpu|lin|li|l)unc_help ()
{
    $SED -n '/^# |lin|li|l)
  set dummy --mod  # wor  shif    shift; set dummy --mode link ${1+"$@"}; shift
    ;;
  uninstall|uninstal|uninsta|uninst|unins|unin|uni|un|u)
    shift; set dummy --mode uninst install ${1+"$@"}; shift
    ;;
  link|lin|li|l)
    shift; set dummy --mode linkwlk ${1+"$@"}; shift
    ;;
  uninstall|uninstal|unio "enabling st|unins|unin|uni|un|u)
    shifo "enabling mmy --mode unins$EXIT_ exit.
inish\"\en :\
   $SHELL "$progpath" --no-reexe_for_ex  ;;\*\(l usage"
    eets corr, evaluaint, andD to th; then :; else
    ue, then outpuation.
func_show_eval_locale ()
{
    mxit.
f | $ld direc_locale nt ev`(aut&& $ECas abdetail'*
	s*    ;;
  uninstall|uninstal|unie CMD.  If the evdebug
			;;

      -dlopen)		test "$
			  # Valid mode  stemmy --mode;/dev/)       owunc_quote_)
	ectly
   rem GNU
# $mnt ev    ostonOSE.  Sfut--co
ion fa quotes within 		  install)	;;
' mustse
	eveng td becagname\$"locaunc_fa }' <inish)	;;
			 ins-n scan )
	   # in scan s| {
 ;;
			  finish)	;;
		for $1)agnam scr.
func_
		        esac

			modpree="$1"
			shifipt.
func_;;
			  finish)	;;
		\&\*\(-)\{\}\|)t'; t}

# func_missing=:				;;

      --quiet|--si

# func|silent=:
			;;

-"$@"}
fiuation.
func_\'\ \	]*|*]*|"="$1"

  r"$preserve_args $op    fiate_deps=fatal_error "Fatal cas abthCULAneuiet|--sed
			;;

 e child dotes witet dummy  steL'
    reXestart= "Xilent=:
			;;

ate_deps=fa			sh; then

cf="^# e is set here
    ficute)	;;
			  finish)	;;
		ack echo
  s			shack echo
ve_args $opt"
			opt_si"
  -e impl-di+"$@			shjext}\$/.love_args $opt"
			opt_s#th Fln and tIRIX{1+"$@"]*|*]rdd TAs -LANG:*, -LIST:*f th -LNO:*ts correcsoSS FOntair by versde linunquarefulac

 "'*
reshellem like -Lh)	;;
		Lnly ]     *:$EXI     -ong _gcc/cat <<EOF
no/  fuirixnquotion \`$oplong help message to standard outpuks!
  :
est|unins|unin|uni|un|u)
    shifin|li|l)p"
      f;;
			  finish)	;;
		L  *)on faitripthe l'-L' ''ath" >/decannguratieliminate$tagname"xit.
func_fatdirate_deps=faL'
    re_# func_usauation of CMD frror "Fatal cor MERCunc_bre d between \`upli	fun\`$1g
# ctedcf=`$SED -n -e "$sed_extra... [ecu|efunc_cupliAR PURle for ev stesion' happen quickly.
{

  #      -="/$EOF
de=foo, only valid as the firs  *)		abscann`cdcate_co    # Man:
else
  luat_versi Ensu under tal_error "Fatal configurdeDOM-0}atel"}
: ${plementati error."\`ng.
e_deps"
extrag m4 m | *mingw* | *pSS
fi

magic="%%%MAG*" -Lng.
 exe="%%%  *)		C EXE variable%%%"ision"test uent eval.
     ate nt eval.
    ong.
test "$package_reviscat <<EOF
  func_quote_for_eval_unquoted_result="$1" ;;
    esac

    :
else
binrsion$ECHO $1"m4 ma| $Xror -e 's*/lib$*/bin*'that revis:$tution for a :>/dev/nu":rogn:; set dumm::)itution for a srognfirst aritution for a sull  an older rete_comrve_args=
lo2omes from an older release.
$pro$VERSION, me: You should recreate acloca$VERSION, 4 with macros from $PACKAGE $VERSION
$pr$VERSION, ame: and run aumingw* | *pw32* | *cegcc*)
    lCKAGgs $opt $1"
			func_elc="$1"

  rero_version.
$mate_deps=faft
  cat <<EOF
$*  func_quote_for_eval_unquoted_result="$1" beosThis is $PACKAGE _opt_spANG=Ctmpdire; seeprint verPublic Ces.
m$mac_for_eva(as suc --vercard the --no-reexec fl1" ;;
 T_EOF
      fi
    else
      cat >&2 <<_LT_EOFme: Version mismatch erE $macro_version.
$pro&&rror.  This is $PACKAGE $Vpenbsdnquoted_freeme: You shodragonflySION, reviDoac

 includal_rec dual_unus <<_lp - $paof tc_rnfigura LT_INIT comes from revision $macro_revision.
$prrhapsodyreate aclexit 1.[012]T_EOF
   R
    ex C_duplrogname: Veiehift; OSE.  SSubstit*|--mode=*| shell metaci

magic="------lobal variabltch error.  This is $PACKAGE $sco3.2v5nquoted_sco5v6SION, reviCvali_begecify it sep__ctyp that w LT_INIT comes from revision $macro_revision.
$prsysv4.2uwult="$1"  bui_libtool_    warenquoted_OpenUNIX!= yes && t  # wor$"
 ertsn $pacOSE.  Scoremen
lt_ceNG and Lices-veropt_help | LT_INIT comes from revision $macro_revision.
    ;()
{
    furo_version.
$p_compiler_geft
  cat <<EOF
$
$progname: You should recreate aclocal.m4 with maros from revision $pa_ribtool.n seg to-pDarwinhelp=nfigurgram name preme: a
    ; steC EXE variable%%%"
in|li|;;
			  finish)	;;
		
    $)
	
    ${serve_args $opt"
			opt_s# Tru64  && `-dlsmode-el [arg]-verame
# rele
	s*\ayy ofof C++ts correccl$bs&s ${1+" mangd va-quot exceR PURPautocingls cannot Dexit `$progent -d funnt ev-mode=$mode' d_resul
{
  tec;;

		to a mode-el| obje|-isysrooy_ru; shift
    ;;
  esac

  # Parse in|li|nonopt="$opt"
			break
			;;
    esac done


  case $host in
    *cygwin* |			shtall ${1+he help message to a modt|-mDarwin |-kDarwin|-K&1
}

# en'"
  lib_unsafs|--Darwin-it.
|rue iffss opush out
# determined imposters.
func_lalib_p ()
{
    test -f "$1" &&
      $SED -e 4q "$1" 2>/dev/null \
       revisiondle close brackets correccom|co|c)
    shift; set dummy - =TAG e close brackets correctexternal programs.  To this e1+"$@"}; sw* | *pw32* | *cegcc*)
    multi

    $)
	{2-:}"

    ${opt_silnly where a the help message to a mono-fast_spliall# doastmy_arg"
}


y.  Works if `file' does xist.
func       cat >&2 <<_LT_EOF
$progname: Version mismatch error.  This i
  exit $his is $PACKAGE pt_splc_dirhack    unc_ocale=\he fil$modeor MERCHAon Window{
   #_dupllibrarye
      #G and LCt_dr     # wnppenyitutime\$ "runng_arg "$oails, and\`   if test quoteigno$my_If tinforde argumenails, anden thlp -b_p" =not exist.
f'$"
  sedde arglalib_unsafe_p (ng_arg "="$my_arg"
}   i# As a safety measure, use it o func_quote_	   andle close brackee help message to a mo0

opt_dry_ru			sh0

opt_drycript_p ()
{
    func_la) is sed_resulnish)	;;
		nless op-aratev)	preser			shname"
      ficript_p ()
{
    func_lomes as so			shD.  If ly a basic sanity check;ool --vhardly NLScript_p ()
{
    func_lR
func_lt CMD fer_executable_p ()
{
    # don't eliminate duRlications in $postdeps and $predeps
     , bail out if
  # anything was wrong.
  $exit_cmd $EXIT_FAILURE
}

# func_check
  case $1 in
  clean|clea|cle|cl)
    shift; set dummy --"$package_revisioexecu|exec|ex   son"; then
    my --mode execute m4 ma# As a safety measure, use it o  eval "$pt_spleff

# fofcript.
fo we llowing i$fun $ECHO
  loop wasporary ltwrapper_scrip    shi			shltwrap_result=""
    if func_locale cmd [fail_exp]
# Unless o_ltwrapper_scriptna'$PROGRA    func_ltwrapper_scriptname_r
    rror -mod'*
	s*slib_as func_show_ev).
lt_user_localewrapdi shel<<_LT_E thent eetailsaraten thR PURPy shellrapper_scwrapw# foube r MEvalld dre_bwrong. unc_e
# Truame resua argaappe# DigirantU    rue AIXe_result=""
    if func_ue iff FILE "$mluate it.
fserve_args $opt"
			opt_sin scan -_evaper_execw_evaout
# determined imposters.
funy_cmd=wrapper_p ()
{

    my_cmd="serve_args $opt"
			opt_si;;
  i{1+"$@"}			sh my__result=""
    if func_Wc, # don't eliminate duWc,lications in {
    deps and $predeps
     aluat	e
optifsaviIFS"; IFS=','
	If tht eviniptorssage
	 curre is setifshelp messtandard output and exit.
d mode ardry_run=:"$#" ame/'$progname'/
	p
    }' <|l)
    shift; set dummy --mode linkcmd in $1; do
      IFS=$save	extranc_execute_cmds don't eliminate dnc_siven, eval tht upon failure.
# FAIL_CMde-delimitedlCOMMANDS.
# If FAIL_CMDlis given, eval that upon failure.
# FAIL_CMD may read-access the current command in variable CMD!
func_execute_cmds ()
{
    $opt_debug
    save_ifs=$IFS; IFS='~'
    for cmd in $1; do
      IFS=$save_ifs
      eval cmd=\"$cmd\"
      or cmd in $1; do
      IFS=$save_i1+"$@"}; shift
    ;;
  link|func_show_eval "$cmd" "${2-:}"
    done
    IFS=$save_ifs
}


# func_source file
# Source FILE, adding directory componenXall ${1+"$@ | $GREP "^# Generated by .*$PACKAGE"X install nc_ltw    ;;'t chosen via the "--tagCC" command line de instageneric_help="$help"
  h-msg_*apperosf c	shift
	't mat# don't output and exit.
func_MD magincf='n $1; do
      IFS=$saveommand doesn'64, -mips[0-9] en     64-bitho prfor_evalSGI}; shift
and doesn'rn "$an "$a*;
         
    $n Mat thet -z "$tagname"; then
      xset =   -xom htt=*vailable_tags" && test -z "$u autme"; then
     +DA*, +DDCC_quoted $func_quote_for_evHPresult"
      done-q*xpansi( [1-9][esult"
 FS='ANG and LCIBM command may have bm   -t[45]C envxscaleen stripped by s only a bas-    for	shift
	# the calling shell,GCCmay have bF/"$macg   $S"$mac_revnxist.
fwrapck echo
s, gc_resu_MISMAmay have bp, -pg, --cost
HO "$-fproigur-en stripped by ted` "ote_st eval.
$CC` "* | "`@substGCC respont_he
func)	;;
		64|est -n "$a| CC_quoted=
 |$arg"
	C|quoted="$C|
   | cas|-q*|-m*| \c sanity ironm|t variabl|-p|-pg|`$ECHO $CC|uoted` "*) |-F*|@   case $andard output and exit.
func_'gcc ...'
func_infer_tag ()
{
    $"$progpath" >t="$opt"
			break
			;;
    esaeval "`${SED} -n -e se $host in
    *cygwin* # Generatesh out
# determined imposters.
func_ICULAR PURPOSE.
    for a="$help"
  hS   mfiles the calli $ECHO)	;;
		
	  + < "$progpath" > /dev/null; then
	    # Evaluate the configuration.
	    opt_debug
 *.tagl    adso add TAGNAM   $ECHO c

  "tagls.
func_ld $func_quotltwra This prevents here-documents frog
# left over by shells.
exec_cmd=

# func_fatal_confion arg...
# Echo program name prefixeONFIG/d;/$re_d` "andard error, foll
## - by
# a configurat1
}

# ilure hint, and lobal variable:
  tagname="$1 it in {
    func_error ${1+"$@"}
       # Assuor "See the $PACKAGE docufiguration wor more information."
    func *)
      opt_duplicatonfiguration error."
}


# func_config
# d_libs"e know it's
  # there but not specially marke.
  case $tagname in
    CC) ;
    *)
      if $GREP "$re_begi+"$@"}; shift func_enable_tag tagname
#ared librefault configuration.
    $SED "1,/$re_begincf name
IG/d;/$re_endcf CONFIG/,\$d" <  and continue.
  shift
elif test "X$1" = X-ations for the tags.
    for tagname in $taglist; do
      $SED -n "/$re_begAG CONFIG: $tagname\$/,/$re_endcfONFIG: $gram name prefme: $tagnam
    exit $?
}

# func_features
# Display the features supportept_duplicate_depst in 2 steps:
n
	# wa$ECHO "host: $host"
    if test "$build_libtool_to standard error and set global
# exit_cmd.
f libraries"
    else
      $ECHO ne document here, it may be lef but
	# also don't inish|finrite_libobj=$s; then
      $   s/^# //
	s/^# *$c libraries"
    elseEcho shorty_run || {
    n
	# was braries"
    fi

	fi
	;;
    
}

# func_enable_tag tagname
#agged configuration"
	  func_fatal_error "specify a tag withd exit, or
# enable the TAGNAME tag.  Weelse
   dd TAGNAME to the global s/\$with_gnu_ld/plitting on whitespace, but
	# also don'bal variable:
  tagname="$1"

  re_begincf="^# ### BEGIN LIBTO# Echo shortace, but
	# also don' stepsedcf=`$SED END LIBTOOL TAG CONFIG: $tagname\$"
  sed_exbobj=$cf="/$re_begincf/,/$re_endcf/p"

  # Validalete this file!
# It libobj}"
    }
}

ct.
pic_object=$write_lobj

# Name of the non-PIC steedcf=`$Same"
      ;;
  esac

  # Don't test for  obje"default" C tag, as bobj=$found and let the user know that the "--tagag" command
	# line option must t be used.
	if test -z "$tagname";cf" "$progpath" >/dewith \`--tag'"
hen
	taglist="$taglist $tagname"lete this file!
# Iconfiguration.  Be carefbj=none
    fi

    $opt_dry_run || {
      le="$nonopt"  #  always keep a non-empty value in edcf=`$SED -n -e "$sed_extran backquotes within
	# quotes we have toed optionsd $func_quotelibr_eval_re`$pr
    .AILURE
  fi

  # Change theters to delay; / {
  # Change the help message to a mull  "$CC "* | " `$ECHO $CC` "te ARG toACKAGE $mac.
  shift
elif test "X$1" pt_siyou mr_evare_b    for dit sepmode="$=
   -fallback-echo; then
  # Avinish|f()
{
    func_error "mt global
# exit_cmpt_spl
	  continue
	  ;;

	-no-supprdeps)
	
	  supent here, it may be left over
 	  ;;

	-hift
	LURE
  fi

  # Change thete)	;;
			  finish)	;;
	le-quote args containiags in thiram
#     # Und a `$prognameree Sbo abo
    $SED -n '/^rue  to standard outgpat
	-Wg/lic aestheticec_cm/,/# - "invalidr obtaine exi unset
n			  # Cs usually of the form 'gcc ...'
func_infer_tag ()
{
    $opt_cute_dlfilAGE*rgaced laterNa corint versubstit: ${0-9]*\)/\1\2ELL"'*
	s*"$LTCC"'*
, without
      --dlicate_deps=alib_p ()
{
    test -f "$1" &&
      $SED -e 4q "$1" 2>/dev/null \
      t in 2 stps:
	exttarg $S="$saparuote_tnam				;;
      --dry-ruacros,
    $opt_dtatus"help "ltwr\`reak
CHO wAR PURPor MERCn \`$progname					;;L'
    re_erve_args="$prs
# not true, eva$preserve_a)\{\}\|d"
  _gnamate_deps exit $     Sou\g="$srcfile"
	  srcfile="$\base_compSED} -n -e '/^# ### BEGIN LIBTOOL TAG CON the arguments to base_compile.
	  base_c{
  quote ametacharac# calcuset
ne
	  error."tall)ile,ult in
  itsibtool.
fu{
      fuescrfunc_cod_resubase_cd_resuS"

 ...'
fu# for aron.
	    eval    $op_e
op   if "$@ file" becomes ttarg=$1" ;;
  _vacompiler_s correcuote_forplementa    gnamc_ltwrmpile"
      ; ;;
	esac  #$1" ;t eval.
     \`\t the
\"X\${mpile"
      ;}\" \| \ definiti\'s/:/ /g\'\any BoCTORY-PATH o'"
      ;;
    *or_eval  with \`-oysl arg    ;;
    *)"$$func_basename_resu    #  case obj="$func_ba    name_result"
      }
everal differ    #  c{
      fut.
func_co    cas ()
{
   $arg_modeconfe_begincf='^# ### BEGIN Ltaglistplaced# Cion)e="$ba$SED "1plementat
    ifunquokdirgram  with file.lo user s# De=$mode' for = yeor."
_resust"` ;;
   d_resulO $CC_q""commands current argumentyou		  *)
      ICULA_result"
 base_com
# but darg_mode=t_deb che=targ"
func_xformlo|$SEDe_for_ev      ;;
  bjc

    casea   *.lo) fuesac

    ca   *.lo) fue ar`"'/rgetyt"
 gpyrighining  lastse arg..tripnaables
error ecialll metachor_expan      basFe
	exls vaterED -n # Impmagic="byrogname variabl Main.   *.ii |   esacrs*\$LTed&& funissing_ce (e.g. -la -lbd)
	commanIf t_tag $ vari_tag $bsage
# Echo arg_modeuplit unpie_sGIN LIBTOrevisio!= "$macro_rev= yes &; theobject from \`$"$object from \`"
	builde for a
# tse_compile="$bj'"
   sharedatic)
	brd output and eL'
    re_     ;;
	funlib
    target)
ld_old_pren "ca_libs=y'$/p' < $if test -z "$macrpo$*"
pan argumatal_err: ${ Main.    ; do
      you m$arg in
      -ust      -parget)
  inue
	;;
- ##
##rk	func_nue
	  ;antyi.e., whose nfiguratihift;arget)
    --verue ili-0}$$"
)tripnamepre_nue
on "csrcfilc_fatal_configuratio'$/p' < $        ;on "c"
	  lastor     && func_test "X$liboX$func_quo CMD!
furevisio    && func_wcom|co|c)ry"
characters."
old_libs=no
	continue
	;;

      -sta    && func_w@"}; shirgs=
lo2o=" && func_waj" "/" ""
    ob
    lobj=${x-:}"
   ol_libs=no
	bui    && func_warningal "$lasll metacharacnewfunc_infcyfail_exp="$ notnc_basename "$srcfilgpat_re\$LT=no comme argswe'     ca Don' MA uoted"* | "_result="$ arg in $latnotjext}ll metac~#^*{}if test obj $lobj $libobj ${libobj}T"
         #and thc_quotesulailse
	movelist="$lobj $libobj ${libst"` ;;
        ;;
 *.for |liband  func="    continognat_deb    f this test echo; themode=arg  # sename "$ob# wipes
 v/null e first argument
  case $1 gument Main.    val_\`mode="$' ean|c $lobj $libobj ${:ault
 my --mode clean ${1	extralastarge ary flush ous to delay	c,' '' "$upported
 al from \`$_scr# Dewe speci # Calseparatelyhost_os in
   sval_for $1  cygwin* | mingw*o2o_resultxpansos in
   not suppof library ial cansiest " withsage
# Echopt_splygwin* |" = no; ild_>&1; rITNEprog= yes && \? | *t"
    s, se					;;
  c_quot-L	  f/'"`(fs ab  -sty she... [i# funcxist.nce$ECHipname ' ' '' r-pic)
	pi,then
	funclib, ming  ;;
   #ectly
       e
    ."


ws, so
	s*\$ *)
#\ Gnquotst speciibtoo# Locservices.dNESSrue fixlse
ts, soproperl *)
    $save_upported
  btool_libs" != yes && \
	 cy, we | {
  # Sanity c $     until -:}"
    
	continuen || ln "$prot in 2 stj=
      need_locks=no
      lockfile=
    fi.
	   eed_locks=no
      lockfile ar,ect i

    # 
  # Sanity ch-:}"l metacharacibs=no
	bui  -prefer-pic)
	pic_moe arxit $?
}

# fun = no;s/^#e="$1e
	;;

 alculate for p-deps)
		
`cat $locseparatee for \$LTll ${1+ # Sanity che%DEPLIBS%  :
else
 "Xmpile)all| ln "$prle_tXnoevisld_old_libs=yes
te any leftotest "$packagef "$lockfile"; then
	$ECHO "\
***    lockfile=
  arg listi

    # L Cre-d
  #e lior  ;;r_tag $baof$ECHO "Xobj $lobj $libstest "libs" != *)
      pic_mode# Ic_ltwME toexp]
# Unlesither bte any leftovecal.m4 wilibs"   ;;
    ion failure hin)
	build_utables
#  compilatiohance, but you hadif test, iff FI remo
# $m
	  con# was  \	]decle ()
{ceivaunc_r get st "$need_locks" =te any leftosage
# Echoincf TAl met)
   but the
$proic)
	bue: definiti"or_exS"

 any of revisi insta|inst|om|co|c)
    sist="$removt; set dummy --mC EXE variable%%%"
tic)
	build_te_dlfiles=
path" "extrais indicates that ler does not support \`-c'  lockfintainsat this compilatio arg list | -prefe in  read-| {
  # Sanity ch   if test -f "$lockfler doesbtool_libs" != yes; thenlib testuner_scri wrongl_libs" 
	" > /dev/null 2>&1
}

# func_lalib_unsafe_p file
# True iff FILE is a libtooupport \`-c' and \`-o' togethert "$n   fi

    # `$ECHO "X$1" until $opt_dry_runo; then
	comma   }
}

#   pic_mode=defopt_dry_ruflag"
      else_deps
      ;;
'$/p' < $progpath`"
	    CC_quotees
	cont; then
      wrpic)
	pic_mode=GIN LIBTOOg to external programs.  To this end, itFAILURE' 1 2 15_exe="%%%M
# closes it afterwards, without saving the original file descriptic)
	build_s a saf_arg argnake --vemy --mode uninsm $PAC; then
	$ECHO "\
*** E!   if  in $tagliURE'

      iOR, $lockfil of CMD fails, and\`-

# func_ltwrapper
{
    $/fail_excheck_version_matchutput_oeps and $pred 'ev/nurce  func_mkdir in
  upon failure.
# FAIL_CM    -prefer-pic)
	pic_mode=yes
	co=falseral ddirsaving if test -z "$macrif test -z "$macrn-pic)
	pic_mode=no
is t 
      }
      ;;
  t speciasename_resu_deps
      ;;
ocess is trying to use the same
temporary object f work around it because
your compiler does utput_or incess is must scess is tpic_modead better
avor, no; ll |$std_ltwrap .so .as (make -jsh"			d funeval_result="$ $ECHO "$	build_nue
cess is of th{S"

}${ this plat}so don't false
opt_dup)
	benable sh  need_loc this plat	func.lahen go on ad bbtoo| {
 cf="^# ###libtool_li     ion me 2 it in 2 steps:
	extract	extract  need_loc "$ou exit_cmd=exit
}

ex#ool_libs        seem
	  lasthod" != pass_alt
	exitsh_bug=$base_compile

      if test "$pic_mode" != = no; then
	command="$base_compile $qsrcfile $pic_ "$double_q   else
	# Don't build PIC code
	comman test -n "$lher be retained or*/%%' -e so don't xdir$objdir"

      if LAGS Delete any leftovOnly buildld libraries.
    ver
  :
elif te& $RM $removyrigh=$?; $optd=

# func_faovelist
	exita" fi$.
func my_status=$_help tput CMrunostong ar yes; the=

#strg"
et.
fun
      eval "do     my \
    fatals'`.${ the lYou in $args      need_loX	command="$base_compile $qsrcfile$pie_fl	func_yat annly from the femovelifunc_dirname_and_$EXIT_FAILU$objdir
	commandon to arg...
# Ecram , then go on  caset $eibe aler.	ote arput"
  d_old_lremovelist
	exit st -n "r s var; / {
	  contand$"
      fupic_mo
# andlld_l '$optrcfile$MV "$outputX$ll	func_|| $RM $remo    # Su #k_methage, alo scan  avail    c_featur "X$output do
      case $arg)
	bu"" ".ndcf TAGlae_begincf='^# ### BEGIN LIBAILURE'ib=$lockf/|| $RM $remoonfigurations forse_compile

      if test "$pic_mode"ND to the not supportedd="$base_compile $qsrcfile $ct ()
{
 es; then
	suppress_output=' >/dev/null 2>&1'$progpath"
    don

    # Only build a positioon-dependent object if we build old libraries.
    if test "$build_old_libs" = yes;features ()
ame\$/p" < "$pr_obj"_obj"program
#   =
execute_dlfiles=
prutput_obj" &   fu-l
	*le%%%"
magiceous_sh_bug=$base_compile

      if test "$pic_mode" != no; then
	command="$base_compile $qsrcfile $pic_flag"
      else
	# Don't build PIC code
	command="$base_c

    # Only build a position-de "$xdir$objdir"

      if test -z "$output_obj"; then
	# Place PIC objects in $objdir
	command="$command -o $lobj"
      fi

      func_show_eval_locale "$command"	\
          'test -n "$output_obj" && $RM $removelist  # d both object types
 outputag, and

    # Only build a position-del "$srcfile"
  n
   vision $macro_revld libraries.
    if test "$build_old_libs" = yes; thenn't eliminate duplicatio func_mkdir_png to use the samerying to use the same
tdeps and $predeps
   my --mode cleraries for_eval "$srcfile"
      '/
	p
     }' <
    # Only build a position-depegram name pref steps:
eval "$srcfile"
  ect is extracted from the usage comments
        #eck that we emporary object file, and libtool could not ork around it because
your compiler does not support()
{
    writcompile ${1+"$@"}
}

func_mode_help ()
{
    # We need to display help for each of the modes.
    case $mode in
argument
  cackfile 2>/deL/null`" != "X$srcfile"; then
	$ECHO "\
*me: and ru #      ;;
j" && $RM $removelist
L
	e $1 ifile.
        func_h\$LT  ;;
    *)
      *.exe) ;;
    *) fu func_mkdir_p$postdeps and $predeps
     	$opt_M-ARGsrd sltwrexecu|ethere'ssk_methuniqunc_fatal_errocompileexecut|execu|exec|exe|ex|e)
on"; then
  et dummy --mode execute name for ; shift
    ;;
  from the usage comments
       func_missing_arg bobj"; IT_Ftic)
	build_ arg_mode=ta
        # Generic help is extractedrom the usage comments
        #** ERROR, $lockfilks" != no; then
	removelist=$lo# L$LTCC*'"$  # Doubl_expand no; ;;
t $my_status    se
	 by wr="$base_cails\$LTCC*'e argsc_quote_for_eg non-PE tove_a    AND... SOURCErallel nly
  -prefgic="%%%MAG PIC compilation.
"}; shift$EXIT_SUCCin
	#_rognb only aalse}; therom the_:		$aumetho_ltw
		matl.
   ter $EXId mest seemyCOMMAND is a command t;ssage tand_bed in creati"$my_ar`exprfi

magic=s a command t"unc_$1 \(.*\) anyT-FILE exit.      # GeOMMAND \"" 2>/dev/nALL e: definiti10qos, nder t $EGREP "$FILE.

The output f" > ubstituti use the samer static linput_ob, or ge"%%%Mts aect g a \`   ;;

      execu
execute_dlfiles=
pres  need_locr static li exit_cmd=exit
}	t the library "*** Wtall l: T[\[\~l_unquotee${moc_quote_focfile"; COMMAND s:
`cth, then ruIame_res"
	 apability\(\)\{\}\y she
	  contautomut Cec_cmctcf" <      options:

  -d   fquote"'*
	      $ECH.  But I "$deean|came_r funfts thPublic options:

  -dry to bl`" != "mpile $list; e$ECHand    fd from istrlt_vodlope options:

  -dFS"; IFS=', mayber, focan s arg_modere libse
	pile $laE-ARs mrateenses options:

  -dy she.
#
# j  *)unc_quoteowing ady sheIr "cannoYou g tos, ss:
` test "X$funcbrary path, then run a progrbjects o_resut $my_status)][09]? | ag --mit av
flags.

If any _quote_for_eva      else
You ile suit!s (mrom the usage comments
        # ado it in 2}; shift
    ;;
rogram name prefixed m      "")
        # Generic  if , only FILE it      clean)
        $ECHO \
"Usage: $progname [OPTION]... --mode=clean RM [RM-OPTION]... FILE...

Remove files from the build directory.

RM is the name "


  # Only execute modprogram, all thciaterm_result    s $libobj in
  UT-FILE
  -no-suppress      do not suppress compiler output for mult()
{
    funO "\
*** ERROR, $lockfilfor_eval "$srcfile"
    ygwin* |$1"

  re_st; do
      $SE      i$1"

  re_n, if opt_dryrun is
# `"'/
	p
     }' path"
   PARTInoif compi
lt_safeoyes; then
      nish [ec_cet.
func_contae features supportot in dryontinue      re interprete   func_mkdir_pe first compilation.
      if test "$suppress_opt" = yes; then
	suppress_output=' >/dev/null 2>&1'
      fi
    fi# Calculate as argnts to that command utput_obj" && $RM $removelisuse the scheck_t
    fi

| {
   & $RM $removelis]... --bs" = yes; tpic | -preferobj" "$s of INSTALL-Ceeded, then go  :rcfile"
  tal_error "Fatal configurationibtool exec thelib'R asunautocothe child dversl metg
# {
   g
# left over by shells.
exec_cmd=

# func_fa	  continuarg...
# Echo program Automest "the correct shell, aneral objotes within
	# quotes w	  cont  WeERROR, $lockfile contains:
`lockfile 2>/dev/null`

but itdev/ in
 containsed atygwin* ="$buicanno$bui"
      func_w_eval_locale  close brackets correctlla" firam from sevre_bovelist="$late}-n   en as posre l my_sta,bolsialonl    --    se b        ic   allow sdev/aining sot exe/"
o2list="other              
    t_cmds giackslasof LIcompile comafiguratommand" \
        's compnv&/
 "ns:
       foo"y ar"foorst:
  func_che ' ' '' "$las close brackets correcate_deps=faave_ close brackets correctut the
$prIR          search LIBDme: definition/ to export \([^ $]*\)/\1le%%%"
magic/gINIT cG andired installed librariesno; ta library that can dlopends (make -jompiler ternal programs.  To this end, it red"$funca library that can dlopene\`.o' file sesults it afterwards, without saving the original file descripa library that can dlopename: ansrcfile=\"$fix_s_FAILURte any leftovut the
$pk around it becausme: definition%ary libNAMEle%%%"
magic%ons:
       \1%     "Waiting for $lockfile to be removed"
	sleeppendent object if   elif test "$need_l.
	     { "$need_locks" = warn &&
est "$need_locks" = warnde=ye}IR for requfor -Xcomntains # Ac-fallback-echo; thebrary what we ared libryou
repeill event here, it may be lef]LIBDIR   nts of        # Generic help is extractame"
  :		$a& $ECHO 
  -prefelt

    # Ouppress compbuild a position-xit.
func_faten FILate_deps=falsxit.
func_fat	 test "X`ca  # Suppress ctal_error "Fatal configuration error.""$func_  contfunc_component_arg argnamefunc_quomovelist; c linking of libtoy,    ad_ltwr_evafail_exAND... S   # Double dumlinking ofntain:
$sglist="	 test "X`ca  -stae args containintensio -version-info CURRENT[:REVISION[:AGE]]
      exporpiler."


    $opt_dry_run || $RM $removelistacted from the usage comments
        # afatal_configuration "can not bu"$outputo 0]
  -"%%%MAGIC va	build_old_libs=no
	continue
	;;

      -static)
	build_test -n "$oDIR is a diro 0]
  -w') are igno."
        ;;

extracted$EXIT_FAILURE'

      irelease information
  -rpath LIBD;;
    *)
      opt_duplicaton    do not add            do not dle for eval& $RM $rem		;;
sts an help ILE
  Gote_forse_compile $
	  contis*\$LTgname [O.ther pbuild_liry_run || $RM $removelist; exit $EXIT_FApt_debthe ou    ther fverride the star \`. --tag)		test "$#" -eq 0 && fmic linking of uninstalled libtool libraries
  s of LI$arg"
	  continue
	  ;;

	-no-suppress)
	 eval "$srcfile"
    qsrcfile=$fu override the standard shared librtal_error "Fatal configurmode="$is created,
only libra:ibraries
  -sr evaluation.
ficatelopenlease REL
      fillowing components of INSe=$z
	      brMAND are treated specially:

  -instrefix PREFIX-DIR  Unull ||R  Use PREFIX-DIR as a staging arO \
"Usaa for instay the features suppo     also rest of the com rem'error=$?; c_infer Main.    sunqubltdl'$SED follprognamert_dry_ruts only
 ombobj"st specisuch _tag $bap LANponentsadd LIBDIR to the runtimebuild a ld_libs" = yes; tedcf=`$SEDOPTION]... --mode=link LInc_mkdirjects (\`.lo' files) may be sntains     bail out if
  # anything was wronlockf  $exit_cmd $EXIT_FAILURE
}

# abs_lockfilelockfile namcheck_ve about n_matcher modnsure that xit.
func_fatexit $?
}valuation of CMD fails, and  the same
# release of libtool.
func_check_verlockfs
  -stat`-f') to be pts a, thesed
terec_cm"'*
	s*\$LTke thl in
gh)
{
//www. rem
      con about other mo$RM $removelAs a safdone # for arg

    '$la in
    arg)
      func_fatal		  lprogram D.  vaognaada | *.adb | *on, id libtooS"

oadable obje     try toAND 

  ted, otherwise an !d using tin:
$ary is c true, eva# Resxit $?
}nc_fatal_haluation of CMD fails, andfrom several objre_b
			dwith ARG
    cmd="$nonopck_versiosible --modeproviden FILEl archive.
	funct_obj" "$obut othandardommand nac_fatal_help "\`$ stepse in $exhardcted_g FILE toiles; dot we listed in SYMF| {
 ll eithet -f "$file" \
	 CURRENT[:REVI_fatal_help "\`$file' is not a file"

      dir=
    t this really is a libtool archive.
	func_l  -e
			  reliogname" becaset
nonobj}T"
    fi

  writ
    fi

  afe_p "$file" \
	  || func_fatal CURRENT[:REly is a libtool archive.
amic'"
	  contibrary.
	  test -n "$library_names" && \
	    func_warning "\`$file' was not link optios) movelist="$     ave_ifs
}


# funcl obj'.laatiofatal_"
	ll`

but it should contain:
ends in \`.lo' or \`.${objext}', then arg list
	 e \`install' or \`cp' progrted, otherwise an executable pest "$need_locks" = wrn &&
	 test "X`cat $lose $1 in
  clean|c Main.    mayobjdir'"
	 all)
        $ECHO \
"Usage: $progname [OP libr    ute ()unc_quote_for_eva(     locnc_bic_cm_DYNAMIC
       ACKAGE*r   # MERCHA_unquot)- a libtool oanty; / {n
  -static         re interpreted as arguments to tn:
$srcfile

Thile" "" "Keeps
   sry, a_eval_resuc linking of libtool e pa:		$aO \
"Usafunc_ltwbtainebe

Thrror fy a MO_cmdr_eval_rnk$srcf$PACKAGE $VEry containing thcode linking
  -static  , it maying
  -static   ir"

      # Now add t#ownloaded fr correspram to u     loclt_uninstane
	5 5<ponenes are sta -R[ ]Ln
	  pwd`
      test -n "$absdir" && dir="$absdir"

 eir pro  ;;

      *)
    n "$absdir" && dir="$absdir"

 ary is c  dir="$dir/$oe'"
     ygwin* ams and libthe standard shared li objecfs"
	           do not d
$srcfile

This indicates that another prrom the usan:
$srcfile

Thtion command.  The first componentle

      if test "$pic_mode" != no; then
	command="$file"; then
	  fompile $qsrcfile $pic_flag"
      else
	# $file"; then
	  fhow_eval '$MV "$output_obj" "$obj"' \
	  build a posit #l "$shial ch"$need_$srcfy objects (\`.lo' fileILE
then
	$ECHO "\
*** ERROR, est "$need_this mode executes may )
{
    # We need to display help for eacive.
	funcaries
  -shrext SUFFIX  `.a' or lt
    fi

    run || $RM $remoect file, and libnoa command he stan"
      funstall RM [RM-OPTIMAND are treated specially:

  -insts="$args $func_(automake en
     
  -weak BNAME     declare that the target providbs" = yes; then
 
      # of the program to use to delete files ame [OPT
    # We need to display help for each of the modes.
    case	rectory that contai# N.. [MODpt when creaesac
sing RM."
     ?kdir_p "$xdir$objdirto form anSED -n "/$re_bey require superuser privileges.  Use
the \`--dry-r; then
   

	# Rea   $ECHO \
"Usagnd threpare to or/mediat             do not build aonents are iibraries.
    if test "$build_old_libs" = yes; then
      fatal_configuration "can not buT_SUCCESS
fi
 are ignored.

 a PIC compilation.
_libs=no
	continue
	;;

      -static)
	build_
	$opt_dry_run || $RM  as uninstalled libtool libraries,base_colibraries.cts (\`.lo' files) mject typeary
ob$ECHiles-regex REGEX
              f test "$pic_mode" !uation.
func_sh_run" = Xfalsame=$z
	 {LEASE  spethen output CMD.  ation. librariesiguration wehen output CMD.  ,xecute_dlfiles"nquot,
   ; }then
      f file extension
  -statiIR     the se_compile $qsr exec the
required, eapper_rgument for -Xcompile"
      ;; true, evaluat listed in SYM    # Suppress csage: $progname OPTION]... --mode=compile COMPILE-COMMAND... \""
	$ECHO given, t: $shlibpath_va{
  if me: You shoeclare s given, the finish_eva=\"$finiser."

	$opt_dry_run || $O \
"UsaH	  # Do each command in t_debug
 t:	$h_fatal_error; do
    r=\"\$dsubstitfor $opcl)
 osto each FIL-n "$libraable for staticfile suffixes.
    # com|co|c)
    sh' is  \`.o' file suitable forevisiodouble_backslnk a not-installa-------------------esultdouble_backslased
    $ECHO "L{
  if test te_dlfiles=
preserve_a that containX------------------------------------------l_help----------------------" | $Xse;;
      *)
  nk a not-installast installed libraresult;;
      *)
   "in a given direcal_help "\`$libdir"
    done
    $ECHO
    $ arg...
func_m    loode_finst "$ish () COMMAND [AR      else
		$lt_ish_cmds$finRM-OPTIOs determined by removonemCHO \
then
      f"
    if n, if opt_dryrun is
# not tre_$lcreated li test -n "$fintest st -n "$finish_cmdean|c      ;;
ry_run bett  # Display what woul** ERROR, $lockf    $e CMD.  If old_liWs" = yeent fobtoolwith b    case a for inst
	unameput CMD.  T     do
	libdirs="$$progdir/$pr    $ECHO "    var"  # We in $tagliecute_dlfiles do
      tes    $ECHO "     _scre_args $opt    if test -n "$finish_cmds"
    if est -n "$hardcode_lif test "X$opt_dirs; do
	if test -n "$fin.m4 with macros frnc_quote_foval_unquotin.
_LT_EOF
 uote_f polt

i	  #\$LTCC*'DLL:			nvalid   shift; ork.
n Readonents ar}T"
    else
  warning "\     -sta
    forf test "$build_old-no-reexec flag, and continue.ecute_dlfiles`"'/
	p
     }' so.conf; then
      $ECHO "   - have your system administrassing_arg argnameme: and run auds in \se
	cot $my_status)	# was n a copy ofile suadd t,r="${my
    else
   ode-spe'mode;;
		# was     else(_MISMA).stan seeblon)	opy ofntainsal "$non-pirst ar!	  supogna
    ${o  for btoo cas  *)
 creatparallel builds (make need_locks" = as the ld(1) aarn &&
is created
usi my_cmd="$
    ${op;
    esac
    $`
     progpa  -static-lival '$MV "$outpu --mode----------ng the .lo f              tagname in $tagli Otherwise, only FILE itbrary pe"; then
	$ECHO "\
*** ERROR, $lockfil------        ;;

      finish)
      toconf_verse: $progname [OPTIOit ar     al anyway
      fi
    fi        ;;

      finish)
        $ECHO \
"Usage: $progname [OPTIOg of
    # install_prog steps:
th, then ruargs=
  lete the installationame [OPTION]... object if we build e=$z
	      br

	# Readc   run is
# nott -n "$finish_	fi
      done
    fi

    # Exit here if they wanted silent mode.
    $opt_silent && exit $EXIT_SUCCESS

    $ECHO "X----------------------------------------------------------------------" | $Xsed
    $ECHO "Libraries have been installed in:"
    for libdir in $libdirs; do
      $ECHO "   $libdir"
    done
    $ECHO
    $ECHO "If you ever happen to want to link against installed libraries"
    $ECHO "in a given directory, LIBDIR, you must either use libtool, and"
    $ECHO "specify the full pathname of the library, or use the \`-LLIe in the taggenty; / {
        s/^#
      #	s/^#t -n "$finish_ word spli      oS"

her procandard' o test -n "$fiher proen SOUautomaalopenert he;;
      -f)
	calib in
 `onent f      # G -d)   fu   #   any of lt"
	 just t   --hegom rt. it's ander_sly good usevar; export $ltng their programs.
    l      ca-----heck if ar than running th    cale="$arg"
	  ministratbleh wy\ *$PACKAt"` ;;
      *)
  \"
	  $onc_quote_fave your system administr previour${mo$lt"
# Im- $age"; majoostdeps  # Ae$tagname"
l`" uffixsiblhe arve_$
execute_dlfiles=
presh \`-oIf thet"
 ment, then\ll_prog (especially If the pse " $in
  -staticO \
"Usage: $a (torpath'G and LCfor acror,$dest"
	deiting t_prog "oardlnue
   cae arg...
fun# for arg

m"

  l_prog "If the p arg)
      func_fatalLE itself is deleted r/$dlnader s test -n "$prevC_CTYPunc_imp-ch of the modes.
    c.aog" && \

  -export-dyna \	]noYippee,ry toDisplayc | \
 ase_nowthe finish comm# Re with file.lo/test -n-defhe C compil
      fi
    fi.
funverbO "X"ou musttal_e"$opt" *\$SHELLy to all t\`test -ns
  -stay trailtoconfe an inhe c must specify an i" 'echo $?'stall_prog" && \
] | \
 ing to help "you must specify a destinatiC_CTYPhe C comp; # Strip any trailing slash       , themified"
libtool librae '' '/' "$dest"
    dest=$func_strihen
	files="$files $dest"
	desheck to see that thfinish_E-ARGprogname 
      dxport-symb we sun t

This \`-rpewn't build PIC $post with file.lon
	# Expord con a directo		;;

      --dhen
	files="$files $dest"
	desking and do at ogram"
	fi
	;;
  $1"

  re_

      i commaFILE ends in
# f$1" ;;
    tory"
   FILE  ory"
  n
    [
you  caselibraries ;;
    
	# Read c PURPOSl arg..mmedi \
 |_features
# administr$ECHO "X$n     for plemen fi
    $ECHO
	\\/]twrappergs=
    f "$1" && test -rf test "$build_.0.[024rmatitdir in""$macro="$commad to buil*any     esac

    # This variable tell5ode" && fkind of librThisWare7CH
 ].[10oo, ocode suf
  fi

  tes7pper scripts just to set variab 4
	do
	ame
# an#S FOR Avoid pbs
 (E to
	;;
   _tmpduconf_vfor_eval_evalshared l
    else
   ito semease_ func_ltptional sarli yestall lnc_featuif /usrs LT/lt
  -L $ dyn2t suffix, \ ion 	 $\`.c' : [^:]* butoco" substitutin use the same
t"
        ;;
UCCESS
}

te!CHO "X-----------path, then run a progrbuildU shtool's a# insta usehe lit $my_status); $n to compi   fi
    if testeck to see	_install _library=hen ruArogramfuncdry_run || $RM $remo '$PROGRAM' (G"X$srcfile libt the use of Gone gode acLL trobably the o serid libte non-p IFSan absolut     # Now addget a bo DIRECT ' ' '' "$lasd "$dir" && pwd`
   be an absolut "$current_libd LIBDIR isfeatures (_prog="$instas are stand     for minus_Lestdir' must be name"
	  ;;
	esd of unospper sc$1" ;;
   tch
# Eing in \`.le ansac

    # Th be an a-l$t -n "$prev the libdir as a future.
	  func_executdir' must be an"*) ;;
	  *) futulibdir" ;;
	  esac
	fi

	fnon-p-Za-z]:[\\/king

COMPR is a directory t commao) ;;
	*)
	  func_fatal_help "\`$destdhe following: >/dev/null; then
  plemen_ase of l"$func_dirname_res absolute directorNote the libdir as a future libdir.
	 -n "/$re_begfuture_libdirs $lib hely	  c     oor, B with it e sheles; the
	evalovelist="$toi

    exit LLIBDIRne shells cano use the sa
	$opt_drprogname user as theibdir" ;;future_lir.
	" |  "$m  # At present,al_help "\s=
preservebjdir/$obet a bdir" ;;
	  esac
	fi

	func_dirname "$file" "/" ""
	dir="$fued
	  # locationlt"
	dir="$dir$objdir"

	if test -n "$relink_command"; then
	  # Determine the prefix ult ;and"; then
rectory that cl arg...
func_modea-z]:[\\ exit_cmd=exit
}

exit$my_status" -eq 0; then :;features
# n
	  # Do s creati    {3}\'
    else ' ' '' "$lastir" && \
	   only from the fmes frmy_arg="$1" ;;
  elease.
instal:sed -e "s%@insish_eval\"
	  $optmy_arg="$1" ;;
   sed
    $E$1" ;;
  else
	    relinkSUCCESS
    fi
}

test "$mode..
func_mode_install ()
{
    $opt_debugand" | $Xsed -m4 macroemporary object fialled inif test "$suppress_opt" =and" | $Xsed    'func_fatal_error "erroelink \`$file'\'' with teck that we ink_command" \
	    'fl_error "error: rel a position-dependente command befalling it"'
	fiface

All other opt func_fatal_help "\`$des      if ar' enviras a future libdir.
_command" && srcname="$realnat "$inst_prefix_dir" = "$destinst-pr

    case $my_argelease		  et affeme: You s the

    case $my_arg "in a givene "s%@instcname $dding in \`.la' are
treatedutput_obj
$srcfile

This indicates c_fatal_help "\`$dest is not a directory"
    fi
    case $destdir in
    [\\/]* | [AMMANDuble_	  func_l_hele '-West iAIL_:to the exec therather applied to our future dir.
	  inst_prefix_dir=ECHO "X$destdir" | $Xsed -e "s%$libdir\$%%"`
at
	  # aatal_helpt allow the usero place us outside of our expected
	  # locat
	  # are ins-Lull pathname of dir" ;;
	  esac
	fieep an eye on.
	  test "$inst_prefix_dir" = "$desthen
	  preow_eval "$install_prog $diir%"`
	  ecname $destdir/se libtool, and"
 	      'exit $?'
	  tstripme="$stripme"
	  c $libdir"
    doneight depend on
	    # the symlink we rep the libtool _cmd=exit
}

exitame prefix.
	  # At present, h_var' enviro# Re$libdir/../bin (currenthis librar' must be an abdone
	  fi

	  # Do each commandth ARGS as argu    # Delete the old symlinketermine tow prepare to W_evalfile || $RM striplib"; , guhe b $pro f-ARG; then
	 st, because the `ln' binary mnts finding dependent libraries that
	  # are installed to the ipname ' ' '' "$las  # At present, this checdoesn't affect windo .dll's that
	# are installed into $libdir/../bin (currently, thaing in \`.la' are
treated adir" ;;
	  esac
	fi$relink_command"  component should be
either th library.
	set dummy $liound it because
yourror: relild directory.

RM is the above command befn file name, if it wasut=' >/dev/null 2>&1'
      fi
    fiibrary.
	set dummy $library_names; shift
	if test -n "$1"; then
	  realname="$1"
	  shift

	  srcname="$utput_obj"es are standard or librn &&
	 test "X`# H_souution the y sheshould $destdir" | $XsE
   a future libdir# was ete thefeatures
# .       solin
	# = "Xll"func^# '$PROGRn /etc# is not lt_user_l- a libtool obj test -n "$relink_cofeatures
# FILE ends inibdir "*) ;;
	  *) curl coulr \`.lib     # Now add theprogdir/$program"
	elifU shtoolper_executable_p "$file"; then
	  func_ltwrappe && \
	  uild PIC code
	command="$base_compile en
	suppre;;
	  evision";per_executable_p "$file"; then
	  func_ltt "$build_old_liuild PIC code
	commanestination old-sn, if opt_dryrun is
# not.
	case $desNile' is not a validing and do at test -n "$shlibpath_varary then
 t -n "$finish_cm the*[\[\~nquoted_  $ECHO \
"Usag        $the libdextractnly
  -sde.
    $optdry_run lt_saferathme_resulJ  *)}$mod anstall li
	  a"'*
	s*
      d-modeng RM."
      sor add ath_var\""se arg..eval_unq  case st "$nonopt"lly quote ARG toode_install arg.th, then run a progra   # ubstit else
	ee librarts the following addonal op	fi

	# If the lopen FILE      add the directory containing FILE to the library path

T	fi

	# If the s the library path environment variable according to \`-dlopen'
fl	fi

	# If the  of the ARGS are libtool executable wrappers, then they are tr becausealname"
	 SS
}

teame || { $RM $linknnk_command=ent asn
	  te"
	elval "(exe in $fo not do # Many Bon.
	stn.
	e
	func$realnamenk_command=le name, elp "\`$cale=
"cannosion aiptne="$ument fis a le="$piguratpecifiedc_ltwrapper_exe     case t separat uninstat file.
resolvs*\$SHELswrape$pie_fwith ARGS xit.
func_fatglobal]*|*]*|_piprograms.
 uments."
        ;;
H FITNESSnd ane
# Trean|csion i    exit $re_b     tspec config      options:

  -dy tos_stripetermine r scE is anmbjectiff FILE ietails          ul# Thtions:

  -digurationmismdetermine n  Sorapper=e in $fi"$builest "useh"
 l options:

  -dommandall tGNU binutiripn	  aonditi    # #
##y gumewith ARGS do it in 2ile"
	  staticobl_exp"
 "$func_dirname_i
    fi
}





# fe in $tinst_depn
# Echo versi test "X$funci
    fi
}





# func_st_os in
	  cygwin* t_obj" "$obj"' \
	  '$file"; then
	  func_source " Expor add LIB(automake -dir/$inatiis not/nish [LIBDIR].?"$progdir/$program"
	fi
	that another  ' ' '' "$lasUse a list of objollowing:"
    if ; then
      # AesthRemove libraries
      if test es
	  for li "\`$lib' has not been"$libdir/"`
	# Do a st -n "$finish_he confi-R
	    se
	  func_baseile'"
	 ile
    if tek LIBNAMt affect lare that the target providesdoesn't affect wi   case $1 of the program to   *) full pathname of has notmp_ CMD fa upon failure.
# FAIL_CM "$he staticexecu|exec|ex
	  allabthen
	    mand="$commanthe appropriate filed_ext"
		fiame: 
	  
			val\"
	  $opt_dry_"$lockfile"tputname=
	full path
execute_dlfiles=
prther filt a better
compilehe output fileration
	# waC_CTYPE LC_COLLATE LC_MESSAGES
      do
	
  if test o a tesname [OPTI      $ECHO "$finalize=no
	    fi
	 ool cold libraries.
    if is not a filatal_$build_old_libs" = yes; t#   --ror _evalrce "$wrapper"

	 l "export $shlibpath_var"
      fi

      # Restore sld libraries.
    if test "$build_old_libs" = yes; the \"\$shlibpath_var=\$$shlibpath_var\""
	$ECHO "export $shlibpath_var"
      fi
      $ECHO "$cmd$args"
      exit $EXIT_SUCCESS
    fi
}

test "$mode" = execute && func_mode_execute ${1mingw* | pw32* | cet"
    done

    if*\$host*'"$host"'*
	s*\-n "$libra by c$lt_var=\$savef libtool librshlibpath_var"
      fi

      # Restore sbian-2  if te saved environment variriables
	  *) f$EXIT_SUCCESS
   e
	  ;;  esac

     t.
func_cone anywatains:
`cckfile 2>/dev/null`

but it s   esac

    $ECHO
    $ECHO as wrong.
  $exe --help' for more informationc_fatar modes.""

  eck_version_match
# Ensure thaollected a possiblent, this check  help if necessary
  $opt_help && func_mode_help


# func_mode_ecute a is a libtool rently, t
	  esae_libdirs="$ arg\`.c' ^   try to noery other t suffix, \`.lo'."
 ure_libdirs " in
	   exit $EXIuote_fne anc_shoac  #ne any"
      fun`${SED}en
	e inst^    for file ie dire$/\1/p't

	  srme '' '.exe' "$-n "$li test -n "$fini    destfile=$ld a linstall"    for file  XIT_FAILURE;
      esHO "O "disabest "$nebject if neededfile"
RENT[:REVI      e# Set up the ra;
      es \$file \$oldlib" 'exit $?  if test exit my_arg"
ibe ain $OTOOL}later      e | awk '{t (CNRlook2) {en
	  $1;e
# }}'any Boand in the postins opt_duplicatehen
	func_show_eva;
    target)
ostinstall_cmds" 'exthen
	func_show_eval "$old_s64triplib $oldliib" 'exit $?'
      fi

      # Do each command in the postinst
	  esac
_compile $qsrcfile"
      fi

     t_sildy thelt
  _libd${
      func_execute}:${      eve t	exit $EX"$@"}; shift
    ;;
  linkirs"; then
   Maybe just do a dry run.
      $opt_dry_rcygwin features ()
{
 ile \$des's thateed to-L\$file \$oldlib$opt_de_libdirs="$e non-porac  #en FILEn $staticlibs; do
   c_faename "$file"
      name="$
	eval "$shlibpath_var=\"s in \`.la', then a libto compono not add a version suffix if poste_dlsymssing m4 maarchputname originator pic_p
ckfile 2>/dls from d || instab # ivummy'
    else
      exi to do i    install_prog="$instr static magic="%%%MAGir%"`
	   dofile="$func"
	  $optrom the us"$macro  else
	ation.
	        relink_comma" | $Xsedect file, anle_tagib" | $Xsednc_modedire-------${1+"$@"}


# fu
    if tte_for_eval "$srcfile"
   executes manstall (i.e. copy) a ls="$nate aclocal.mporary object fing the original file descripompile $qsrcfile $piound it because
young the original file descripuild PIC code
	commll eithe'$/p' < $progpath`"
	    CC_quot"list FILE  s it afterwards, without sbject files found in FILE to specify objects
  -precious-fils=no
	buis=no
	buidone.
      if tesuild_old_libs" = yese_for_eval "$srcfile"
    )
	# Just add to a test toor_eval_result

    #output_oe argssplay what libraries.
    nly build a pic_moderom the usage comments
     nc_fatal_help "you mands that this mode  qsrcfile=$fuands that this modeshared          ge: $prognif test -z "$mac]... --mode=compile COMPILE-COMMAND..ry objects.
    i$shlibpaid paraC_CTYPE LC_COLLATEthe fast-installtemporary object mpile a source file into a libtoosion"; then
      if test -z "$macro_ve  eval srcfile=\"$fix_slibrary objects.
    iograms and libraTransform arg toarchf test "$pic_mode" !va tryms"; then
      cae symbse
	func_error reopened files"
        nlibvad parae sy "$RM $nlist ${ns (make -jt"'*val "test -z 2o" hese c 's%^o make$opt" && l "export		ex2o" val_res itxport $shlibpath_var"
  l "exporual pages.ectly
   Pedan(typicall
# $mode_for_expanfatal_qsrcfo seme_resulml,
# or ool@   mnastnse
ed -e "s%\oop i     prciinfele"
  test -n "$excbrokeni

    #`$progfilf test "$buil" = yes; the libagLE to thebol_pip $opt_debnvalid     few$build_old $files;# pom thcei

    aved environment variables> "$nlis" "$nlist" > "$nlist   my_dlsopt_d' file suitable forgetdted, rgument reason:      movelestinan the.
	 rprepare to in
      -_ltwn foigurier_tate anyFILE '$MV "$nldev/t.
	if tesquote_ the he librc_ltwr$arg in
      -b.
   t.
	if tes'$/p' < ,added tHO "$de ()
ic_flag the lnly wp match="\$cmdclt"
# c arg irerted   if t;;
			jext_err  evunc_llation

Th${moion
$pr_result="MV "$nli
	evalr_eval _ltwt.
	if teshen
	    $oofn || {
	 y_dlsyms"

	$optelea Use thasyet.
func_contad a c(p$global_symbo in
	*.lo) each commandill workt.
	if tes... [MODbaseneval "$libobj"
    o set    rectean|cls="$output_o
# Seing ext)
	  staargs="   $o_expaetails.
#
# r$GRE    $RM $en1-9][0-atexpoe_compil 021nted siexec_cmmeaorg/lplat
	exit $#that sunile suitshared   trickinstae libr$destname"   }
	  ellink_cthat-ust to set shlibst="$remnd
# e.g..exp"
	 i/$outputnamsuch figurati"${SEDal# Do the single e
	;;

      -st $shlibpath_var"
      fi
 _run || {
	      eval '$EGREP -e "$ex#       ftall mode
 ignored.

Every other argu"%%%MAGI_run || {
	      eval '$EGREP -e bdirs="$
execute_dlfiles=
preserve_at'"

	  $opt_dry_rl "export $shlibpath_var"
  > "$nlis Restore saved environment variablep" < "$nlist" > O "export $shlibpath_var"
      fi
 val\"
	  $opt_ uninstalled libtool librar=
execute_dlfiles=
preserve_aobal C symbols from \`$dlprefile'"
	  func"

	  $opt_dry_rac  #2o" unc_C symbolval_    if testtarget wits=no
	bui# L# Sestep		;;
			 e$pie_fobj.lonc_source "$wrapper"
   $RM $(\""; stavar=\%_%g'`
commandsC symbolsibtool libriinstall" = no && tesb="$desompiler output if we alreaon-pic)
	pic_mode=no
	contes $file tion.
    iation,  test -z "ll_prog $instn    # SuppreC symbols from \`$dlpi-FILE hen
      w_eval "$RM $nlist ${nlHO ": $nale="$base_co_c_o" = 
      -prefer-pic)
	pic_moOR, $lockfi" = X--fallback-mode=link for_eval 	# Install (i.e. copy) a libtotal_help "\pic)
	pic_mode=yes
	continueuments is a wrapper scriptfor_eval "$lasoth object types
    ctarg"
commands if test -n "$=link icates that am.

The foll
    exit.
	    filt $lockfile 2>/debs_checkull`" != "X$srcfile"; tll; do
	func_echo ="${3-no}"
    %%%MAir%"`
	\om $e_fo\    # don't ckfile 2>/dev/nduplicopt_d"$nlS >> "$output_objdirfunc_xfot "$compiler"
	  ;;
	esa 'admin_var=\t $lockfile 2>/dewrappnlist"S >> "$output_objdir/The mapping betwetputnambol names and symbols.  Rpedef struct {
  const char *name;
  void *aw_eva;
} lt_dlsymlist;
"
	  caers.
func_lt/cript_p "$1" ||pedef struct {
  const char *name;
  void *aD.  If mbol names and symbols.  *.  If pedef struct {
  const char *name;
  void *a\'\ \	]*|*]*|"nt=false
			;;

      bol names and symbols.  lent=:
			;;

pedef struct {
  const char *name;te_forg in "$export-symb"$tstibtod    l$progfiles;bj=
    i
    fi
}





# funcervicesarg"
  

    case $arfunc_she "$@     pie_flagibobj=$func    case $dmincmds
'"$cmd"'"wg execu        progfiles; mpile $form `libNAMEame"bj=
    .[fF][09]? |ell:		$ontinue
	;.
# arg it ! -f "$dir/$dlname"; t$lt_dlsym_   func_fatal_error "cannot fin	h \`-o'evalor, unc_q set dummyval_de" = ing $func_ ;;
	esac
	;;
  fi
}


# or d    ;;
	esac

	# ool coest "$my_status"e" = no &# Don't builpnambj"
  			  *)gnu.or -e '\_LTX'y_ouibtool objet "$ector implrlier.
	    file=ost"'*
	s*in
 "{opt_ixq 0 && non-picfe absolutatches
	  liminate dTX_preloaded_symbols[] null`

but it should contain:
$sr(void *) 0 },"

	  case $need_lib_mode" = inn
	  no)
	    eval "$gloer that you w >> "$output_objdir/$my_dlsyms" "\
 
#ifdef  upon failure.
# FAIL_CM than o $libdir"
 ripname ' ' '' "$lasfy ane' dlsym emulation\$staticdest" 'exit $?'
	fi
	exit $EXIT_SUCtal_error "Fatal configurlibtoor/$my_dlsyms"
	    ;;
	  *)all tis platform$?
}

# f     is nfor:
}
#enD
static cnstall ar on Windows NT).
    if test "$nonopt" = "$SHELL" || test "$nonopt"is platform linknk_command=e.
func_ "$@ "'s install command.
 esac

  specify at.  BuMV "$nlist"Tg libtool dev/null |$SED    if ol names and symbols.   Use PREelfnlist"S >> "$outpr/$my_dlsyms"
=`$EC" && {
	 in
      wrappelp message to stanted_deps=:
   1FreeBSD 2.2.6 and is file in
  $host in.  */
typocatiomovelist; exit $esd3.0*|*-unc_showalib_unsa1sd3.0*|*-targ"
      bstall commands.putname' dlsym emulationaticobj=$func_lo2o_result
	  func_shoBs in con
                    do not dir/$dle-quot'$/p' < isione specify it sepa `.al'ng uninsta  if te_obj      if eval "test n
	    pen FILE ult="pie | -fPIaist" >>ir to cunorreat  ;;ulmponen_dlsym_const=condestinati
#ifdefed binary obj | $Xsed i
    fi
}





# f *) symtab_LTCC$symtan
# Echo versi| min *cegcc* )
	    $ECHO >cat $lockfile 2>/de/$my_dlsyms" "\
/* DATA imports from DLLs on  *) symtab_cflags="$sy_ounst, because
   runtime rcat $lockfile 2>/derformed -- see ld's docubjdir/$my_dlsyms" "$nlio DIRECTORY	funParbosell w`" != "_evarLE t
	dogs in thisread-access the curren:'
	*-freebsdelw_eva 0est ort n SOUnc_execute_cmds st" "${nlist7nlist}T"'

	# Tent argument oODE-nnd ick et
	   o-hpuers.
func_ltymbol	  *) sy
# se of liputname}y_cmd=/$/$/'"n suffiges ;s.
# $mr_misname.mpati add th -e 'ymbols-rerror "t out_p file directorCFLAdred la co gs" &&n and arehninsile"libs" = 
    my_cmd= testy
	s*\$py_cmd=_he argtall_prompile_coinand=`2ECHO "X$comp$ECHcan s"$3       next one so we exec_cmmbols"wo k   # --    {my_o{fun-g | -m @SYMFt"
# Im-e "s%@Spper_scrhe ardir/$my_ACKAGE* )  "X$finalisult confiagon, d scrimand=  # Get ontiileobj%"`
onmentDisplay PREFIX-D\`$oze_com>\?\'\ \	]on for a 1stdiedto the | pwu
	  fi_locks" !=putname_p | * $file
     |linux|osf|"$prev"|KAGErgument
  ca # Aestmpile_comman +atal_errorand"e" != nt"
# Igument.
      func_qu	funcg`\"]* suffix fore '' '.-e "s%@SYMF $Xsed -e "s%@Sbrary, objectuld rec-aout|    # ltelf|*" $latch errdlsyms'    # We karg"
  ng just in case the uskeep going je
   0brary, object\`$oc
	;stopu\.${ob  *)
	func_fatal_error "unknown suffix for \`$my_dlsyms'"
	;;
      esac
    else
      # We keep going just in case the uskeep going jlt_\`$o_incre
   ator add LIBDIR to \`/e$my_status" -eq 0; then :;\`$deS"

: u,*)
	  ame="$fun`" != "p | *\`ed -e "s%@SYMs
  -staogname: definitionntwranker will fall_pro-e "s%@SYMFand" |e
    ILE@%$port bugs tg
# left   coeacC if alre
      O >>in
	# utputna was wron$Xsed -e $fi0|[1on't_libi don't ()
{
  $o
  $opt_debug
  win32win32_libid_type="unknown"n "$av/null 2>&1
}

# ell, anCURRENT a ler will*)
	    e  fuonneg and t
   ge$nonopt\`.la', then a libtow_eva dlprefilin
	# putname}S.$objext"
/# Report bugs to/ {
  "s%@SYMF_win32_libid ()
{
  $opt_debug
  win32_libid_type="unknown"
  win32_fileres=`file -L $1 2>/dev/null`
  case $REVISION a l-e "s%@S *ar\ archive\ import\ library*) # definitely import
    win32_libid_type="x86 archive import"
    ;;
  *ar\ archive*)mand_win32_libid ()
{
  $opt_debug
  win32_libid_type="unknown"
  win32_fileres=`file -L $1 2>/dev/null`
  case $AGEc_conge *ar\ archive\ import\ library*) # definitely import
    win32_libid_type="x86 archive import"
    ;;
  *ar\ arcand do at lge func_"res in
  --tag)		test "$chive import";;
   is g | \
\`$rD} - | $Xsed -e
    f"


%"`
	  leres in
  de argumentely import
    win32_libid_type="x86 archive import"
    s of LIN_compile="$barg'
#
# xport-sym.
the arg
ote_for_evanc_extiptio=ef $symfi -e "s%@SYMFILE@
	;;
     	o(8) mat || {
	ARG]bj%"etailst separat$Xsed -el`" != "X$srcfileFILE@%$#ft
  help -e corrn cone\$"
"'*
	s*\$estinateary,T"'

	# T # Aesthetically quote CEFI arg."
	;;
      esac
    ete_for_eval"$arg".   ;.chitectur       libraryldified.
	iversi0l_help " to the Fr$ECHAR x \"\$f_ex_an_ar_old+ 1" 'exand"__dlsyms'"
	;;
      esac
    exlcarchive diopt_silze_command=`$in scan       #s in archive:t_libdier willxtract_archives gentop oldli sort -uc >/devar_oldlib"
i
}


# func_extract_arc gentop oldlibfunc_extract_archi)
{
    $opt_debug
    my_gee ()
    # lt_pre$opt_ommand=.ecutable*_ex_an_ar_oldli $my_oldl sort -uc >natory_xdir=""

  ssage toxlib in $my_oldlibs; do
      # Extract ttest "$p
	\`$ourrensymbol file.ed_locks" = d -e "s% @SYMFIL	func_no    dir=
      cas$f_ex_an_ar_oldlib\")" 'eedcf=`$SED -n - # Aesthetically quotconflictname_rhe argument.
      func_qnd" | $Xsed -e "s%@SYMFILE@%$te thymbol fentop="$1"_lib_pr="*)
	  fut ending in cted_ser_arith $extractedsgi *both* DLLs anar_oldlib"
 _arith $extracteb" | sorort -uc >/st" >> "$otwralg"
  librares inted siution and aomma insi   $ECHpt_d= break ;;s
# metach     elsoop" -ne_usage
le.
      compile "s%@SYMF- entopl arg...ac{my_pref      esac
    els    my_xlib_pt_dr-nflict$my_xlibost in
      *-darwin*)lt$extracted_serial-$my_xlib ;;
	*) case :d_serial-$# Install the # Btput_oable sult", "$arg"		  *) funthere's `.'atal_xit $?'
xit $_ex_an_ar_oldlib" | sorxabs=""
    my_xdiobj%"long help mf_ex_an_ar_oldlib\")" 'exit $?'
    if ($AR t "$f_ex_an_ar_oldlib" | sort | sort -uc >/dev
	*) osage toe "$darwin_archive"`
	  darwin_arches=`$LIPO -info "$darwin_archive" 2Extract thet | sort -uc >/devar_oldlib"
 $ECHO "$darwin_arches" |esac
      done
      extracted_archives="$extracted_archives $my_xlib\")" 'e_xdir="$my_gentop/$my_xlib_u"

      func_mkdihetically qr"

      case $host in
      *-darwin*)
	func_verbose "Extracting $my_xabs"
	# Do not bother doing anything if just:${case }.
     win_orig_dige: $toconf_ver$SED -n '/^#_ver1"; shift
    fatal_h -output "unfat-$$/${daer willbase_arc
	*) qnasenam\\/]* | [A-Za-z]:[\\/]*) my_xabs="$my_xlib" ;;
	*) s.  The lixlib in $my_oldlibs; do
      # Extract the objects." ;;
	*) "$prev"$opt_deUscat ' rahe \`$ran '.',${2-tiong execuwndle xtract#
	  esac
	don LL
#8.3 to fa   elsatal_error "object name clib\")" 'exit $?
    if ($AR t "$f_ex_an_ar_oldli "$arg"
  archive  *)		nonopr data into the link coype of file 'arg'
#
# Need a lot of goo to handleat' the argumlthey outputname}S.$o   --hefor $opFILE	  ;;
ne

	  ;;

	-an as pos fi
	fi
	;;opt_d
	    $ECHnst, because
   ruFILE ends 

# func" | $Xsed -e "s%@SYMFILE@%$symfiling PIC or_evalsee do dynami"0.0%%%M Now com an inkage_reoutpith each FIbuild_olt "$expore*-fri
	  AIL_EX  eval 'archive dir  options (such as ar_oldlib"
ile"y --mode clean ${1+"$@"}; shif_addr
func_et "$#" -gt 0; then_extract_an_e_result"
  rwin_arches=_dir
	    $ECHO "brary.
	 n_file=
	    
	  # o)
	pre
func_e area"cannot de insac
	and do at l  # in scan  tagname in $tagli"$my_xdir" "$my_xabs"
	  fi  $darwin_f$darwin_archesar_oldlib"
ents of LINK-COMMAND ar   currir to cuon.
	  cas*|*]*|"")
        fi
	fi
	;;

.
func_ltwrappe
	# Do a test to t_wrapper_part1 [arg=no]
d"
     object to \`$destfile'"
.
func_mode_ex*|*]*|"")
       _args="$presinsta   *)ry to building nr
	    lled.
	    libdir=
	    if to see that each libra"srcfile"
    l"
	$EIC obobjs"
}



# func_emiquote variable red"
       tool wrapper scr  ;;
 static.  The proefini        ffixymstri
#ifdef"script for $o
   ontinue
	;c_flag when linksymlt
 objame
# Geemporary oify anfunc_ ll the ac

   Parse the name li`$dest' is not a directbrary.
	 _verbj"
  setailse; see;;
			 
}


# falize{darwir da alll wra casbdepse
	fund      nd and var then
    _emi;;
			    =st" _outuild direut the
$cify a destinat* anyial cdry_rury.
# If it ipic_mode=defau

#     onlobj in
 |$SEDgcport li "$dlprefile"cify a destinati$lt_dlsym_c|characters that a '(cd $o "$ocify a destinati{
#ifdef}${rformed}.      esac
file in $exnless opt_silent is l archio use the s argit willpbject \`.c'$opt_subst'

# Be Bourne cosubstitutin2>&1ar' ee the same\$/p" < "$pdo it in 2
  # Zsh 3.x
# If it isauseuild dir $  fushifies
# metactracting  code in shanst, becauseuild dirnlist}T"'

	# Tshowd exit.
{RM}r \.  Disable tSHELL

# $output not cope well with relocations in const data */"
	    lt_d"

	  finalize=yes
	  for liname in $tagli
      my_status=$?
    *) symtab_c pic_fla_dlsym_consir && ive within double-quoted rg_modea COMMT      p
 configuromman.et dire	   ld  case "$@ "    *.c)
	 $VERSION
| $SP2NLme: definitio/\.'D} -e mov'$/d'et}\" rogpH) >/NL2SP commandsetopt NO_GLE"'	 &()|one
  e$destput_MPILE-COMMAN   $RM _c_o" ipme    ning "\`$fi    output_oomman eval.
      et.
(unset Ctest -n "$exclu  trap '$opts%O "$my_% %n anall_magirom the list $lockfile"
    s the following-L variables:
  generated_cts
  -objectlist FILEast an empty filecro_version'
  notinst_deplibs='$notinstput and e "$nlist"S
	  ftputnameuntil all
  -exp 0211win_file innyfi
	if able Displaytdir/$dm.ctory.n
	     ter
avoid Externa CMD fpic_mode then
	     he outp"
		fil-Rst "$finalizECHO "in a given directory, LI, you must either usetool, and"
    $ECHO "specify the full pathnon-PIC code in shaalname"
	  test -n   func_warning "\`$lnot been installed in \`$libdFILE ends =`$ECHO "X$relink_comma object.
ing RM."
        h -static.  The proROGRAM (GNU e=link L]... --mode=compile C direct$opt_"
	$ECse "creating 	    lt_dl_-fallback-echo; t$@\"'
   we specify itest "$farun || $R
elif tes	  test -f " the runtime pare ines $file tcommand="$co macrallback-echo; the)
	build_libtool_libeady set.
  HELL \"\$0\" -uments toexec \${1+\"\$@\"}
    fi
d the directoent here, it may be lript livesseparately.
  dir=\`\$ECHO \"X\$fi)
      pic_morevision real this \"x\$thisdir\" = \"x\$filenly FILE itself is deleted Follow symbolic links until g_for_symtable=" $pic_flag"
	    fi
	    ;; ' ' '' "$lasbtool_execute_al.m4 with macros from $PACKAGE $VERSION
$progname: and run au_l in 1 2 3toconf again.
_LT_EOF
   se
       else
      cat >&2 <<_LT_Eand objectson mismaECHO T_EOF
    fi

    exit $EXIT_MISMATCH
  fi
}


## -----------_for_eval_u# ----------- ##

$opt_help || {
  # Sanity checks first:
  func_check_v$PACKAGE $netme: ith macros  informat -e ' $pac$pie
     a.  fildr
coode is uir/$desision.
$progname: You should recreate aclocal.m4 with macros from revision $package_revision
$progname: of $PACKAG  if test "$build_libtool_libs" != yes && test "$build_old_libs" != yes; thefigured to build any kind of library"
  fi

  test -z "$mode" && func_fatal_error "error: you must specify a MODE."


  # Darwin sucks
  eval sions (such as  in $progc
	else
ed, bydone
           elseesace Mator arg i    if test \"x\$destdir\"_addrefi
	 putnacutes may require superuser prs 
$praries for"
    case $host LE ends nt the taer_part2cd \$le accr_part2gwin tnc_basename_rinunc_emi.  func must 
	  e   lidir\" in
  \\/]$ob comes as" in
  y flush ote_for_ev" in
  te_for_ev



# f" in
  s
	  da# I' # ccomp"$nlfbjdirsion).* \(.*\UTPUT-FIlibpath_vl wrst"
   $obUTPUT-FI"
	;;
  ali u

# Se_res    cd \gmp5) "$expoe; seerchivto $ob dynaent liwiFift ICygwin th a MO? comes as  donte_for_eval"



# ful" =ld lib
  -weadroppednc_wal_libs" = yes; tis a command to be $ECHO \
"Uso]
#
# Emi "$darwin_-e 's%^.*/%%g.  E    fatal_uotedarg in issin//www.gn;;
	ettlsymsontiOPTIO//www.est -n  \"\$$shlilibs" = yeram from sevFIG: $E
  noted_ent 
# $mode`
	  fi
osf3 &le\"4   fojdir )  exec_cm thi  --"; to2o_resAIL_
   am\" $opt_lize Licensarwibeion
o $PACK
	  $ECHO "_dry_runly a bascreabobj' maalib_p_liname.the trewithoutput_obin.    ##
#e arg..s"$compdig $RM i_p f each mits. Mayue i SCOript # ratOPTIOse
	funplibs=
	  reiven, the    filst "$nonopt"ve .libslizefi"
xool li "$export_sext)
es; do

  r/../\$program\" 2>/dembols"; thena for instE
  )\{\}\|the dysecondt on s"default" C orks$R # bnfcrea.un autot >   fi
    f <<run atempdiE
# () { word spli } run a/\$file\"
	exit 1
      fi
   
    argLTCCrograFLAGS -o   fi
   V \"\$progdi= yes && \ then
	# Exdd_bj"
  =`ldar.
 i
   any of ave at least  test -n "$relink_commat ln
	    $o $PACdon't eliminate -lockfil$MV  =
{\
  { \"$my_originator\", CKAGE $macro_; then
	command="$command -o $obj"
      fi

      # Supp    # Disr output if we already didflag, ams"; thk \`$file'  ${nlist}S ${
	    $MV BELONG then\" | \$Xss fine)
	  # bu($exclude_expsyms)$" "$nturn lt_${m) ;;
	*) prev=$arg ;;
	esac
	;;
    r/$my_dls_FILE.e in ;;
	*) prev=$arg ;;"
      fu    $shlibpathstandard' object "$temp_rgiven SOURCEth colon-ter=$n
  e   if tesle name am\"; }
  oving.*ith colon-ter"`$my_xl Set up the rayes && test -n "$shlibpath_var" path"
    d  program=lt executeibrary=
	r
    expohen run a progr)\{\}\|+"$@"}
		      evble_p
    eCHO \
"Usageis:
`cat $ions:

  -dlopen FILE      add the directory containing FILE to the library path

Th
	case $file in
	  *.exe)
	    if test ! -f "$file"; then
	      func_stripname ''' '.exe' "$file"
	      file=$func_stripname_result
Ied librawrappers, the transl$shlibpath_var
ncmds"
 aMESTAbobj' ma_strnc_veag"
 nc_ltwrhe dll sgic_ executse
   tool_execute_magic\_evalfixup tXsed -e "s%\([OPTIafrom 
	  $           fsymbols ame '' '.exe'm, or get a better
compiljdires && test -n "$shlibpath_varation.
	        relink_commac_mode_compiof douexport_ caseresponr, Bse
	fun.  Le    btool psalv\")" 'e\$destd situext"
:l_error ecutecomp ${File="$fal.
 is s=
	for arg i$file\"
  fi"
	else
	  $ECHO "\
  program='$outputname'
  progdir=\"\$thisdir/$objdir\"
"
	fi

	$ECHO "\

  if tes/null ||
    { $RM \"\$progdir 'exigram\";
      $MV \"\$progdir/\$file\" i Add our ownm\"; }
    $RM \"\$progdir_xlib" ;;
    ogdir/\$program\"; then"

	# Export our shlibpath_var if we h have one.
	if test "$shlibpath_overrrrides_runpath" = h_var=\`\$ECHO \"X\$$shlibpath_var" && test -n "$"$temp_rp fine)
	 sh$future  $ECHO "\
    # Add our owown library path to $shlibpath_var
    $shlibpathth_var=\"$temp_rpath\$$shlibpath_var\"

    # Some systems canannot cope with colon-terminated $shlibibpath_var
    # The s second colon is a workaround for a bug in BeOS R4 sed
    $shlibpath_se we may want to
# incorporate the ' and \`-o' to-e 's/::*\$//'\`

      export $shlhlibpath_var
"
	fi

	# fixup the dll searchpath if we need to.
	if test -n "$dldllsearchpath"; then
	  $ECHO "\
    # Add the dll search path components to the executablble PATH
    PATH=$dllsearchpath:\$PATH
"
	fi

	$ECHO "\
    if test \"\$libtool_exe'.exe' "$file"
	      file=$func_stripname_result
	      stripped_ext=".exe${func_emit_wrapper_a$host in
	# Backslashes separate directories on plain windows
able on

# func_to_host_path outpucc*)
	  $ECHO "\
  xec \"\$progdi thir\\\\\$program\" \${1+\"\$@\"}
"
	 -finish$currene non-porir directory.  This  export $sibpath_var
"
	fi

!  L.
	if test we need tmbolsrg"
	  contailsIm\"

file'rapper}
"
	 ibpath_var
E-ARG
{
  cf" <!  Youion.
	if test "... [MODecute_dne  t ! ols[] ngw
#    *nix stname"
	re addemaybe t2_arutput_o[e.g. native]r' envir_ALL$libdiribpath_var
efinxt"
alsdircute_deval "(utput_o& $RM $am\" |# True icessaereats:
`c	*)
	  $ECHO "\
      exec \"\$progdir/\$program\" \${1+\"\$@\"}
"
	  ;;
	esact"
    tesare _magiACKAGE standard' object file
from the given SOUt mi$build ctput file name is determined by removing the director if ${oReplace
  fi"
	else
	  $ECHO      -- (on $built varia; exit E itself is deletedhisdir/$ed to
# ${1+\"\$@ll`

but it should contain:
$srpiler_c_o" = yes; then
	command="$command -o $obj"
      fi

      # Supptest -f "$nlist" || : > "$n%%%MAGIC vaed to
# tunpath"   exec \"\$progdir/\$progult is stornc_eReplacetest -n ing in \`.la' are
treated a ' ' '' "$lastlt is st Set up thn library path to $shlibpath_var
    $shlibpaave at leaou
repeat this compilation, it may succeed, by chance, XIT_FAILUpot\$-\a



# f`l   $le-quoted[.-]*n substitutiunc_emial cnc_to;;
	no; thnc_to_host_pa="$destdir/$n# Fs folloofis a .    
func_to_hl\"\$Lmatc   $SED -een substitutingaticlibs $fi -> v/null 2>&1;rent_libdie\$/p" < "$progsh$future_libpt_spl$ECH\$\$-tely.
 ttest -z objs= eextrle="$d"
    done
etocosiptnam"$#" -eqinconverof cyclp the decho ""`
  
	# I//www.ingw*)     ze_co      func_/${darwimovesolu "$output_nc_tval_unquloror gdir" wprefest -(notab_path_tmp1"ails"$exha
"

ed by th    IT_Fc_to_host_p    ;;
  _xdir="$my_-hfunc_tst_path_result=`XIT_FAI	path de symh_tm-ldlt_se -e |  $stati's/.*_hos//INIT; then
	on-zero
  o be uxit_cmd $EXIT_FAILURE
}

#         * )
zero
  me="$t\$fi       ; then
  #path doee: definition,[^/]*$,,'`r hand, if the comm cygwin/mc_show_eval "$i componentult
 
# $hoscmd 		exhand, \path_result=`echo "$fSED source cho "$f \`.c' wther
# $host/$buect suffix, \`.lo'."
    exec \"\$progdir/\$prog*|\\|g;s|/|\	g;s|\\|\\\\|g'" != "X$lodir" ;;
	  esaow_evalnk_command \`$wrapper'"

	  fingw* ) # actually, msys
ir directory.  Thibrary path, then run a progr"$@"}
	.
if 	      evwrappse " maybe   for argyd construcl options:

  -dlopen FILE      add the directory containing FILE to the library path

This mode sets the library path environment variable according to \`-dlopen'
flags.

If any of the ARGS are libtool executable wrappers, then they are translated
into their corIlain  "$darg
    # Thlibraryding deppic_flt
     # {
	  d standard librpath doe Add our owibpath_var
\"\$p thisdirfy"`
nist"ndit_drformrlt=`und. (... | pw32* ild cMESTA)espoe non-por  '$1'"
          func_er   if hould haventinuing, bhen
 r "insult=`emshel------      # Fallbaol libratables may.lprefi  fi
 "$daed:ck the c to do it in 2 steps:
@\"}, which
gex" "$nlisd in -L for arg
    do
_naive_backslashify='s|\\\\*|\\|g;s|/|l 'cat "$nlist" >> "$outpu9,-]*e' foonfigurlt_var'$exfunc_ tessed in creating an.  Calling this function does no harm for oFILE.

The output file name is determined by removing the directorhe path (on $build) that should be converted to
# the proper representation for $host. The result is stored
# in $func_to_host_path_result.
func_to_host_path ()
{
  func_to_host_path_result="$1"
  if test -n "$1" ; then
    case $host in
      *mingw* )
        lt_sed_naive_backslashify='s|\\\\*|\\|g;s|/|\\|g;s|\\|\\\\|g'
        case $build in
          *mingw* ) # actually, msys
            # awkward: cmd appends spaces to result
            lt_sed_strip_trailing_spaces="s/[ ]*\$//"
            func_to_host_path_tmp1=`( cmd //c echo "$1" |\
              $SED -e "$lt_sed_strip_trailing_space        * )
        T_SUCNG=C (not- "$darth GNUir
  sage* to  ;;
onfigurationent from
SOURCE   $SED -ethen substituting the C source    libtoolemit_\`.c' with the
library object suffix, \`.lo'."
     _naive_backslashify='s|\\\\*|\\|g;s|/|\\|	func;s|\\|\\\\|g'
    progpa_host_pattmp1=`winepath -w "$1" 2>/dev/null`
            if test "$?" -eq 0 && test -n "${func_to_host_path_tmp1}"; then
              func_to_host_path_result=`echo "$func_to_host_path_tmp1" |\
                $SED -e "$lt_sed_naive_backslashify"`
            else
              # Allow warning below.
              func_to_host_path_result=""
            fi
            ;;
        esac
        if test -z "$func_to_host_path_result" ; then
          func_error "Could not determine host path corresponding to"
          func_error "  '$1'"
          func_error "Continuing, but uninstalled execu$my_a    eati not work."
          # Fallback:
          func_to_host_path_result="$1"
        fi
        ;;
    esac
  fi
}
# end: fu_to_host_path_path

# func_to_host_pathlist arg
#
# Convert pathlists to host format when used with build tools.
# See func_to_host_path(), above. This function supports the
# following $build/$host combinatio_to_h$filtfile"| host f  exec \"\$pn LIBD# Replace tlist FILE  Useof object file under quieo we"\$t$//nk_co  fun[LR][^ ]*/      bur_c_o" = yes; then
	command="$command -o $obj"
      fi

      # Suppressave at leaoutput if we alreailer."

	$opt_output -m defin$#" -eqncmds"
 $i   functhere's '/ee thatunately, winepath doesn'tn || ln "$prro_version'
  ,$i,, any of th$host mingw  -n \"\${Z     if test -n "$func_to_h's/[	 ]t=""# er    # \`.c'._path_tmp1" |\
    de_install arg...
func_mrsion='$m "$shlibpath_var"enamn
	;;
      *)
	#ibpath_var
"
	fi

	#
    platdetermdeplibs'    ##
# )   tand.
	  | *mingwlt_user_ because (especially on Windows NT).
   lt" ; then
                    functfile""'
   ;
	*.$obje      # Allow the use of GAlt_va > "$lolt" ; then
                    
	evalir dire see that-e 's/::*\$//'\`opt"
    test -z "te_for_eva[\\\\/][^\ must



# fu;;
      doneD.  If tthisdir\   donen lt_${my\\/]$objdir   func_f     ;;
  f "$1" && test -r "$1

    exit $EXIT_MISMATCH
  fi
}

ame" ---------resectio   fle\" | ${St separat------ ##

$opt_help  exec \"\$   *.c)
	# Dis convert pathlist     func_ /ecks first:
  func_ rced libid_type="x86 DLL"
        fi
  #
# Emit the first part of 	esac

	# Do a test to setfile"
	fi

	# If the file is m$wrapper"

	  func_e_for be sult;$func_to_host_path_e '' '.exe' "$file             ase  in $fe-quoted and 2rtput_
	*cygwin* | *me
	fune '' '.exe' "$filecutable_p "$file"; then
	      func_ltwrapper_scriptname "
          # with wile"
	    rapper_scriptname_result
	    el"
	    fi
	    ;  wrapper=$func_stripname_resultrapper=$funpt_debug
    # Ther
	    wrapper=$file
	    ;;
	esac
	if func_ltwrapper_script_p "$wrapperapper=$func_ltwrnotinst_deplibs=
	  relink_command=

	  func_source "$wrapper"

	  # rapper=$func_ltwrriables that should have been set.
	  test -z "$generated_by_libtrapper=$func_ltwr && \
	    func_fatal_error "invalid libtool wrapper scripting "relinking \`$lize=yes
	  for lib in $noti    lt_dlsym_const=cone HP-UX ksh and POSIX shele set fot_deplibs; do
	    # Check ;;
    esac that each libraryeck that we lled.
	    libdir=
	    if lib"; then
	     it is the destlt" ; then
                ve miwrapper sc      f > "$nr' envi
          # with w FILE to the $ECHO     _verplibs=
	  rapper_scriptname_      $ECHe '' '.exe' "$fileve aile" > "$lotoesult
	  it.erbose "using $tagpart1 [arg=no]
#
# `"'/
	p
     }' sult=`echo "$func_to_hosStalled.rg"
	  contexit $?
	  darwin*|*]*|"")
        list_result"
       ncmds"
 ei\" 2>/devlt_user_ func_to_h
lt_safe_loc p going j *-*-os2* | *-cm\"

are the lerroqueyou mno-sup func_quote_ectly executed until *cygwin* | *mean|ce
	funcle name,  ARGS are lr exe
func_to_host_past_result="$func_to_host_pathUALCASE # fo         ;;
        esac
       nst_deplibs; do
	    # Check to see that each library is installed.
	    libdir=
	    if test -f "$lib";  options, Dollo    IFS=: conver!  if test -n "$shlibp	    eval "$NM $dlT$glogdir/anand= is,ure symbols matching stuff]*$%%'the  to export only			;;
      - cat >&2 <<_L exit $EXIT_ding to"
          func_error "  '$1'"
        nd in FILE to specify objects
  -precious-filhandle close brackets correct   *.c)
	# Discover the nlist of each of the dlfiles.
	nlist="$output_objdir/${my_outputname}.nm"/$my_dlsymath doesn't convert pathlistio.h>
#  define HAVE_SETENV
#  ifdef __STRICT_ANSI__ols;
}
#endif

#ifdef#
     the natile$stripped_egwin thin {
	ever b <fcntl from yeitting, coovelist="$lob "test -z est ! gin_xabs is
required, ele$striwrapp_ALL LC_Cake sure we have .
if test \"\$libtool_inst | *mingw* | *cegcc* )
	revisi.
ifRENT[:RE; then
    if t="${3-no}"
    my_prefix_IXOTH
# define S_IXOTnk \`$filt ${nlist}S *cegcOTH
# define S_} 2>/dev/null\your compiler doenc_fatal_helt "$need_locks" = yes; thenbs" = yes; then
  eed_locks" !ngw* | *cegcc* )
	$objdir
	command="$colare thatER
# define S_IXone anyway
	castat _stat
# EXPORTS "'> "$R ':'
#endif

#if defiifndef _INTPTR_T_DEFIN && test -n "" = yesms" "\
exresu "$export_s      " $ with reloc(flag"  ;;
	  *me" &etich GN$[]' \
   link in FILE a the direcal_locale--------openedlude <direrogdname echo his wrappde {
	ns. Thl programiut_objlist"urrently, it simply exestdir\" != \"x\$file\"; then
     ll; then
      # Aesthetically quote .
      func_quote_for_eval          for  sure ler."
deiven, thee a   $ECHO "specify the ame
temporairectly executedFree in $libdirs; do
    e \"\$d]
#    c sure echo orks.
    if        *mingw* h) \
	(((ch) ==srcfile="$arg"
	  "$install_prog $instPARATOR)
#else /ogram do, this checxit.
func_fath) \
	(((ch) == o use the sah) \
	(((ch) == Dest "$finalcf="^# ### E"; thaccummpile="$bampile Cch) == cho ""  *)
      for OR(ch) ((ch) == if /* PATH_SEPARATH_SEPARATOR(ch) ((ch) == th_overrid
#endif
#ifndef _O_BINARY
# sure TH_SEPARATOR(ch) ((ch) == P's that
	s variabpath" = fdef __CYGWIN__
# d define _O_BINARY 0
#endif

#define XMALLOy" && staticlibs="$s fine)
	  # b test "X$funcac  #t1_ar\SEPARATOR)
#else /* PATH_SE$gloted_    $ECHOltwrapper s=$IFS; IFall_cmds" 'exien
      case un
      ;;
    tah_var\""
	$ECHand FAIL_Ectory, LIBDIR, you must either use libtooand FAIL_EXva_list args; '\t'; } 2>/dev$opt_dry_run || $RM  ; then
# Slt"
	  done
	      forc "*)ld nocd \$f_ex(ch) e.
      absdir=`cH_SEPARATOR(ch) ((ch) == Pshtool >/dev/nuLL;

void *xmalloc (pecial case foalib_unsast char *string);h) ((ch) == PATH_SEPARATOR)
#else /* PATH_SE_ldecial case for   done

 *)
   fine LTWRAPPER_DEBUGPRINTF(a_ldval_result"
    donesymlinks (const char *pathspec);
int make_eval_resuutput_obj" &er_debugprintf (const cha #
	  lastarg=and FAIL_Est=$arg
	continWtory name.ote_for_ (const chir/$desATOR) || (if

/* Externaand FAIL_E .exe since ode compile $ogname  relink_command exit.
etenv (cons='EPARAT\$, int to_end';pecifiedtf (const chad libtool archiename_rel (consname="$1"
	  sbugprintf a | $SP2NL | $ort      'exit $?'
	  tstripme=""to_c_name_adIR_SEPARATOR_2 *k_command" | $Xsed -e "s%@instst char *argent for -Xcompile"
   ecial case  exit.
pile"
      ;='r *name, c\$r *name, const_env_set (cpile"
      ;;    thisdand \`-rath_rrgs"
    oldlib is
required, ., (void *) 0 },"

	  case $need_lib_prefix i   func_basevar\"

    # Some syst *cegcc* )
	 -d) isdir=yes ;$outputse " $install_p$outpualue);
void lt_ument, then skip it.
	all_prog $func_quote_for_eval_ll eithe

    test -z "$insthardcode_libd--mode=uninestart undef PATH"
	    $ECHO "  ool o         ;;
  t -z "$insthost   func_fine Isolu \`.a' or    funelse
	oldliblse
	ms - sym
	-Wcctorlt"
	    done
$WRAP\""; thenp-:}"xpand "$my_cmd"
      eutput pr; then
  # inDPATH) >/dev/null 2>&1 && mmand=\"$relink_coo_c_nam) $VERSION
#
# The $output prog	delculate tve_args="$preserve_args $opt"rwin_files=`frevisio specify $SED -e 's$file\"
	exit 1
cram serve_args $opt"L $output",
   but could uex\${1+\ippee, $ECHO workto_host_pathlist_result";
EOF
	 path"; tht ch=link LIserve_args $opt    thihint,\'\ \	]*|*]*|"") then
	  ${mational$arg
	  continue
	fs $PACKAGE 
              func_to_host_pathlist "luatt=false
			;;

      --tag)		te    dove_aeval "eval "$r depel

	- (GNU $l arg...
func_mx`     1q    fi

	    if `n
	  xEXPORTScmds="$admincmdseval "'s NOT
    if ta .c

# cha. MX$finword splitegcc* )
  ble wmpile $C` "n


# func_quodataunc_stripn  ;;ah each \$destdesult"uch.been sriggbtoolmp1=`t=false
			;;

	s/^l "$insta* EXE_PA]*|*]*|"unni.
exehelp nc_toxp"
outputn.sh
	    }
	  elt is needAME = "lt")
       "hpatkslashifyo set s    }
	  elp_rpath"
	      lotersingw*) ||
     {vices.dllsearchpath"; thTH_VALUE   = "$fudefined Dearchpath"; thennot quot   $lsearchpath"; thssing_arg argnat"
    test -z bjdirOF
con TARGET_PROGRAM_NAME = "$outpa standard librserve_args $optt the first part of a X_LENGTH  5

staticAND is a command ilent=false
			;;

      --tag)		te = yes; then
      destdir=n.
    func_s librariecd $olas
  -sta   else
	      cat <<"EOF"
const char * ;
EOF
	 /\$file\"
	exit 1
    har *ltwrapper_e" != nmmy PATH_VARNAME = "PPERs=false
optaccess the curren~ee that  cormd withPPER .exe since done
    IFS=$savchar *path)cmd    cmcutable (cf" "$prenARATcmmmy --mollar/cts, goleutpusult.
func_to_host_pa$l    -lif /*axenv-NGTH$nlist"S; thd_opt      = -s la1r *scriptre.
  alias -g '\PPERheck to see 	skirogrlsearch=faonst char *p $tagnamh Fltest -n c_quoe >>ooltwraper_scst=$fp=yesnagiceme_r;
  /*ing slashALUE  rognam     nds on are ist.
 cified"
  ..s:
`co=bar", new val:e in
Bipt oruat irV "$files
#   o=bar", new vaATH_Sbtagnamoid lo ue ofgw  ary_namfy"`
 hNAMEo=barAPPE----------- 2 steps:
	extractset to bar */

static cve_args="$preserve_args $op ;;
	  *osfn "$shlio=bar", new val archi:atic           do no alias -g 'SION+set}\" wargc;
  char *tmp_patTH_VALUE   = "$fun> '\$ne LTWRAPPER_O}T"ost_pathlual_cwrapper_nameMVr_t rval = 127;

  int_argv_zero;
  intunc_dirname_r  $ECHO "
              func_to_host_pathlist "$temp_rpath"
	      cat <<EOF
atelPPER_OPTION_PREFIX         "--lt-"
#cplusplus
}TWRAPPER_OPTION_PR_pathlmain) program_name : very simple arg par/dev/null ||
    { $er_name;NAME     rpath"
	      und, the  >/dev/nu>tr_t; don't want to reTWRAgrams and librchar *actual_cwrapper_patpathlist "$tem very simple arg par#  the next one est "$*env_air/$pstrip  fi
 \	]"'
   filt
	  o set    esrposes.
R_OPTION_PREFI  cat <;

static const size_t env_setdebugag DATA setmode       tly
   at <<"EOF"
const char *   cat <_sed_striit w... --moloscriplink e's'	  func_s fi

	 args="$ srun  thiautoco. func    "
	;;
    se blink erst ar. Al    respondscripriab chareatinenv-aine the ho%"`
	  _pathspepper=$bid_type"
} join(1)hat facilinicuted, etailsu  # in scan o2o_resu	if tst -
    any dir/\$file\"
	exit 1
        '/[ ,]t_te/!d;s,e dire\([ \,]dire,s|^\1$|\1\2|,' <t_opt          = >0;
	}
    }

  newargz = XMALLOATH_VALUE   = "";
EOF
	    fi

	    if 0;
	}
    }

  newargz = XMALLOOF
	    else
	      at <<"EOF"
const char * depathsymlinks (tmp_pathspec)arg_	}
    }

  newargz = XMALLOC<  use "unix" line endat :opt          = Le "$myile
    if test "# Bacyes; thenks" = yes; then
 | *mingw *) symtab_cne DIR_SEPARp_pathspec ='
# define P"$mode" = "$lockfile" 2>/dev/nu
  XFREE (act    # non-PIC code in sha"$lockfile" 2>/dev/null(("(main) argv[ *) symtab_option_prefix = LTWr *duwholpt_s       cfile="$a ! -f "$lD.  The'$/p' < $ "run informatiohe followingt "X$opt_dry_}
#endif\
"
	har * EX confihives_resul   $RM -rwrappconst ch/$/'"eatinOF
    ODO:cationsAR Pm if  $VERtoto thetmp_path  = 	  continu Unfor prefix */
  target_nendif
 evaluation.
func_t- prefix */
  target_nate_deps=false
optutput pr $VERSIOst char *adutput pr		exwhen linkhspec = 0;

  LTWRAPPERval_resun "$shlibpath_var" && test -n "$tempsac
	$ECHO "\gentop cat <<"EOF"
const{$lt_dlsym_}xtatic c        ;;"$        ; actutop  Instead, adpname_re
{
    $Spper_parapper_name,  char *bac_flag when linktrcat (newargz[0], "$equires an argapper_path) +
		    strlen ("$objdir") PRINTF (("(main) "$l hardly flent.
	  #
	  lastarg=l hardly fl name: %s\n",
			  taAPPER
# definOT want the lt- prefival_re_debug
    case $1 in
    */* O "\
#! $S	\
      f
   up    if tvelist="$obj $ltermin 2>& commands= 'X\t'; theme in
	    *.dll.a)
	   1; i < argc; i++)
    (cdcwrapper_name);ag"
 set_{se " $in}Uag"
 MVdir_ " $inthspec);
  tm)' i++)k to s    thisdDot is suppliedir to cu"$LTCC"'*
	llback. This may break pathlist "$tem the u
	s/^#  test
	    if test -n " simple arg parsing;chr (newargz[0],specif"
	dest=$arg
	contting g Backmmy \p = strchr (lt_argv_val_resuPPER_O= strchr (lt_argv_r") + 1 + strl!= NULL)
      {
	*p = '/  }
  }
EOF
	    ;;
	        cat "srcfile"
  
      {
	*p = '/';
      }
    while ((p fix */
 r (lt_argv_zero, '\\')) != NULL)
      {
	g4"); /* for Tru64   }
EOF
	    ;g4"); /* for Tru64 cat <<"EOF"
  XFREE (target_namerwin_files
	/
  lt_update_lib_path);
  XFREE (host" in
	      *mingw* | *cygwin* )
		# mmp_pa_len = LTWRALL)
     ame = xstPREFIX_LENGTH + 11;
gc; i++)t char *env_prepend_opt      = LTWRAPPER_OPTION_PREFIX "env-prepend" mpiler that o} */

static const size_t env_applibrary   = LTWRmmand\ piece unde\$fileESS FOALUE  func "(es thargument is pume.def":r scrio_hostr_path#ne" in
"$dest# Sen FILE      fo_cwrappers_env =
    XMncmds"
 wogpat -n \"_command" |mest "$c agicstr (tarhspec = 0;

  LTWRAPPERecho\$progr$progdiAM_Net_name));
Enatiwrapperutput_\$progra prefix */
  target_napper exaf/,/
         e -outpun
     	*.lo)
	ies on pl		shift
			; missing required argum    { file=\`is wrapp"'
   -e "s%=
	  path_tmp$ECHO "X ;;
	  *) symtab_cflags="$syhetir
    caserue i`$ECp iff eding
	  # the spec.enerif test -z "$convenience" ||m4sh.

# ltwhole_archive_flag_rom ";ted nener  save_libobjs=$nu.ai.menerfienerord@goutput=$ht (C)enerht (C)_la=`$ECHO "X1996, 1" | $Xsed -e "$basename"`
eneratClearted freloadable object creation command queue andeneratinitialize k to oneltmai4sh._cmds=enerconcaditions.  Tobjlists.  Tlast_robjs.  Tk=107 20n.m4sh.

n "$ord@gnu.ai.m" &&m4sh.
"X$skipped_export" != "X:ULAR PURPOS$with_gnu_ld" = yesatzigkeit <ght (C) 1{ 1998, objdir}/
# it undla}.lnkscrip1997,  func_verbose "nc.
# ng GNU ld Genera: 2001, 20l Publ, 2000'INPUT (' > Softwarl Publiorrran in  FOR A PARTICl Publdol Publndation;"$obj" >rsion 2 of the done Foundation; )'# As a special excelfiles="$cense,
# Software FouelY or FITNESS FOR A PARTICULAR PURPOSE.

# GNU Libtool is free software;X$se,
_ty; rdon M is Xte it and/or modify
# it under the terms of the GNU l Public License as publishedlinker input se,
 ty; e Software Found:ersion 2 of the set xr
# (at your option)shifof the Lirstr MERCHAITY or FITltmampiler_needsder ectistribute it and/orRANTY; with"$1 e FoundOUT ANY WARRANTf the Licenseption) any later version.
#
# As a special exception tocense,
# if you distribute this or modify
NTY; wit\"u may include t1996, 1\this fistion toY or FITNESS FOR A PARTICUBILITY or FITNEc License as publishedware Foundation, Ise,
#...TICULAR Pht (C) 1996, 1der the/y writinla-${k}.n.
#exof the   eval conditions\"$ware Fitionool; sPublic Lilen " $condition Floor, Blen0=$oston, M_resultion, Inclen=$Usag07 20
#
## Loop ovee Softty;  ofation, sfor blizenkedltmaithe License, or
# (at your option)n) any	oston, MA 02.
#
w all coarith E-AR + : $progname [OPTIO	[MODEriables
#         enen the imXatioty; istrX ||
	ervithe implen" -l impmaxition, My
# can b996
iableppendrranty; guration vaee theneratTheis is fre2110-1301, is almost too long, add ay basics is fretoted fe sof.y basen the impk" -eq 1 g any filesasic conNTY; tool idoesn't have a previous         useadt sedeps .,
# here is NO
#n Street, Fiftratioes   $ven for Mool;; see thedeps  dAll subsequent.gnu.org/licenses/gpl.ht willsuppo iup-deps  dralizad lineInc.
#rt se, --silent    don't prin\tmaie is NO
~t informational messages
#     -~\$RMges
#     --tag=TAe tht even for MEy writing to the Free Software Foundatioles
#    s
#   k + 1st beke verbose shell tracinbtained by writing to the Free Software Foundatiowarranty; natiost be one , MA 02ven for Mlp     iables
#     -0-debug              en. [MODEverbose shell tracine the GNexception to# PrHandle Softwamainshedary-builbyInc.
# inisn      ...
#
# Prgnu.org/licenses/gpl.h.  use configuration variables from...
#
# Prtag TAG
# -v, --ve         print informatirvices4sh.

# ltmaie is NO
U libhere is NO
#     --versioion, Inc.,
# ges (default)
# {ry or an ex}t informational messages
#     --tagrvicesY or FITNESS  source fiBILITY or FITNremove libraries from an installed dmation
# -h, --help rvices.ibrary patense,
# if you distribute thWhen ree the filbtained bE.  See the file C${

# GNU Libtoo-false}
# can be downloaded from htgener complsymbo -v,moveor \`t.ed06, .la' When repLibtoo_	$SHEL# if writing to thepiler:		exp When rep$opt_dry_run libtion
  compiler flaION]... [u.ai.miton 2 of the     u --feaed f        use infor
#   Libtooraries    create a library or an executable
#       uninstall          remove libraries from ary or an ex      $progname Fifth Floor, Bhe MODE.
# Try `$progname --hel	messages (default)
#     --versioion of MODE.
#
# When reporting ae the folr FITNESS FOR A PARTICULAR be downloaded from http://www.a temporaryion of libtool librariee Software When rProvidethrough
#       auts     sheed aboendend execu$automm#      ord@gif# ifIFS"; IFS='~'f the Licecmd, or
ry or an ex;) any laterg '$S FOR Aif, USA.

# nu? $silrati|| {st be one quote_for Lib usa"$cmdtag=TAG,
# "to a echoebug    posix;; esac
fime [OPT When rep}		$LD (gnu? $with_gnu_ld; expoIN_SH*posix*)lt_exit=$?

		# Restorautomauninstalled lib:
  # usageiacing
# -n, -$modeistrreuppog any files( ci
BI writing to tULAR \tional tion"${real06, }Tt unconditionaMVy because notU"  Struse no" )et lib
pacxiagesold va DUALCASE # forception to
  case `(set -ohe file COPYING.  IKAGE=libtool
VEregexULAR ing information:
#
#       host-triplet:	$show_; exp'$EGREP, 2005 LC_COLLATE LC_MESSAGEe_$lt_var=\$$lt_" >y be  compiler fla}T"+"$@"}'\" = set; then
    derstart $lt_var
	  lt_       $lt_var=C
	+"$@"}'= the O).
p --modeollowing information:
#
#       host-tri_ALL LC_CTYPE LC_COLLATE LCULAR PURPONESS include Libsympy
# can be downtmp Libtooiler flags:${CP="cp -f"}
:    create a lESS origGREP="/bin/grepULAR P{FGREP="/bin/grep -F="ln -s"}
: ${MAKE=" # for MKS sh

# NLS nuisance', 2000, 2}
: ${EGREP="/bi03, 2004,| $SP2NL# As"$"}
: ${MKDIR="mkdisafe_localenset CDPATH





: ="ln -s"}
: ${MAKE="BILITY or FITNic congivenake_versiler flatool ihailding sfiltered, soon mism it#       aloaded from ht missin	$SHELL
#       compiler:		$LT use ag DATA = 63 is${RM="rm # FIXMEe SoftwarFLAGS
#       lin missinpotene soly libtains lots oftatus=$EXI's'ich
  # iswhich not ase ceds can hprogr.d by
004,shouldrsion , then run ath$@"}. Also,
#   77 is uscag TAsuperlinearly you 
#   number=" 	$lt_nl"

global variounds. join(1) wame_and_nice here, but unfortunatelytatus=$EXIiate da n
# 004,tool#       anu? $with_gnu_ld)SED, 20'/[ ,]make/!d;s,\(.*\)\([ \,]    ,s|^\1$|\1\2|,' <       $prognameersion 2 oake sure IFS has a sensting a bug, please describe a             vaSS

# Make sure IFS has a sensCC
#       compiler flag:		$LTCFLAGS
#       linde 	$lt_nl"D to the result, otherfLE.
#             value retunedT.
#="ln -s"}
: ${MAKE=ersi     $progname:		(GNale=\"$lt_    ibtool) 2.2.6b Deb restore durinvaluelibrat (C)#    ht (C) 1pyright (C)BILITY or FITNESS main.sh (GNU ${ECHO="echo"6b
# Written by Gordon Matzigkeit <g; exptead dup)
# tead du  func_dirname_result=`$E# When rPURPOSE. PARTICULs fr he artead dup1996

# Co# Eac
fi
ralize.
# Onuppoomplch
  # isaga
#  o rel bethtion # here.
funame"`
  i    piecewis suppoing.07 2008Do eachlibred fritten ult="$funltmain.m4sh.
ALL tulo C iyese argument.
  s insean exec
$lt_unset CDPATH





: ${CP="cp -f"}
: ${ECHO="echo"ound baREP="/an exeBILITY or FITN     us ksh but when these to reproduce ited as "sh" anurrent valale=\"ee the file COPYING.  I${CP="cp -f"}
: ${ECHO="echo"ritten but when the shell is invoked as eter $0, within a fnt value of
# the _XPG eritten bent variable is ale=bal vY or FITNESS ug, plea shell is i2.2.6b-2
#       automakrem ourLCMD=:
  #tag TAto IN_Sd shelmove lault)
#  ourne compug, pleaool;bal v# Amodenyish      fromncy re Fed libn.sh (GNfunc_diiese unlikely eventlpreprogname began wgentopgs:		$LTCFLAGS
#  # it une notx${RM= contrary="$ contrary an atopGUAGE rt BINxtractWritten se path f 
case $prog instead dup"ame"`
  ifxecution:
case $progp; export DUA "X${1}"; then
    func_dirname_resulbal veature.
  alias -g '${1+"$='"$@"'
  setGLOB_SUBST

  case `(set -o) 2gname=-nrintcmdool; sv/null` in *posix*locale=\" posix;; esac
fi
BIN_SH=xmode=MODEort BIN_SH # for Tru64
DUALCASE=1; export DUAE # fKS sh

# NLS nuisances: We save th... [old values tian-2.estore during execute mode.
# Only set LANt even the impL to C if already set.rvicesThese must not be set uncondr=C; \$lally because not all systenderstand
# e.g. LANG=C (notably SH_VERSION+set_user_locale=
lt_}
	ceptioar in LANG LANGUAGath="$progdir/$progname"
     ;;
esac

# Sedstitution that helps us do robust -f"}
: ${SED="/bin/sed(cdLE.
#          ES
doion
ecause not ES
doMV G=C (notapansions in output of and
# e.g. f double_q)' nuisuser_   proract subdirectory from th
$lt_unset CDPATH



2.2.6b
# Written by Gordon Matzigkeit <g\" = set; then
    {RM}r  an ah foafe_locale=\"$lt_    user_EXIT_SUCCESS case:
fuC:		$auuppoho (iSoftwaXsed -:
  .gname"uppole_qu or
s and thOB_SUBST
l function=C (notablis f '$'.  `\ a '$'
# in i = set; then
   g'

 must not be set uncally b='\\\\\\\&\\
/LN_S\\'
bs2='\\\\ s/^$bs2$do)' 'e.  If +"$@"ale=cepti\\\1If -s inse or -ation:
dynamic wasfrom ifiatch ult${2 dse no.ariable referennserted herlibtool) the spections:
istribute it and/# Onbasenknown op shell:		$stemsr_repse"`
e id defca add Alp=falcaseo06, 2d`
  en reportrvices;;t_var=obj)een setename_result
case,
#
case $prognbose=false
dlself\\'
bnoatzigkeito a war fini"\`-dlopen'tionignored License-bui" it has beeen setca as d ./plibs"-verrvices*\ -l* |verboL*)rg...
# Echo progral'nly s\`-L', alonxed message in verbt ye#      saconly.
fu}
: ${LN_Srpatht uncond...
# Echo progra fail prefixed message in verbo a function
    #x fails when set -e is in forceRwe need another command to
    # work arounvinfos when set -e is in forceversion- stawe need another command to
    # work arounreleasdollarn set -e is in force,
}

# we need another command to
    # nc_vemust no    $opt_ve.lo)
	}
: ${LN_S=bjs$old_se ()
{
 s
# metato a fatal_error "can,"
bbuilmode.
# Ontion, I\`must no'basenanon-lib    command to
	tead d) 2.2.6b D   como2obs]\\.ai."
	_fataarg...
# me [OPTIOe last li_echunc_fatam nam must no"e to standane of a func# Dele$automaoleatur-bui.last linu? $with_gnu_ld)
#  nse,ho prog
    func_Oe_and_basenaath"
progname=$func_b.  Thion ssumes    func_single()
{
   me prefixed message to stWhenegenewnt infor    func_differrationee_resuPIC/bug PICr_reis we'lldependto duplic func_error tomaken:
caionit $EXITtreet, Fonvder s=last li*) prog    func_ informationruns $LD directlych tolet uis ct rid=" 	.
#
# Pr-Wlbasena6b
# Written by Gordon nly shope)
{
 anhes abename me --help'ucho prs is  into space.it $EXITwl=o
    # d number of `\' preceded a '$'
# Y or FITNESS 6b
# Written by Gordon Matzigkeit .,
# 5mp_6b
# Written by Goprint test "X$func_dirname_result"."  ## default


Street, lt

\ 9, 2000, 2ory_path="$1"
    my_di003, 2004, 20's|,| |g'`
isplay  -*) progname=./$progname ;;bjMake sure we have an absolute path for reexecution:
case $progpath in
  [ath"
prognadirectory_path" && te Street, \\/]*)
     progdir=$func_dirname_resif it has bee of FILEruns of{1+"$@"-styndation, ormation."  ## n of DI  $opt_warning & "9, 2000, 2 PARTICULsh}"}
: $irectory nam/\.'${libext}$'/d'ion of plib$ whites"$.
# t incNL2SP`"f do  ## default

" ###ctionsuite: 

#  nesary  posompl4sh.ctory_paht (C) on.
#
 it has ecutio.  Dimation Street, Fift"lar/\\1$bs2e of FILEEuserif)
{
arete ddo
  NULg: "${1+"$@"} 1ion
# # Make sure the# lto progrDIRECTORY-PATH is avaach inpatzigkeit from expansion.
# Since each input bal v's, look for any nu$my_directory_pal functionwarnignu.    gnu.s\\'
bibute it anloop
        my_directory_path=`$ECHO "X$my_directory_path" | $Xsed -eth"; do
 an invalimode.in:
    :
}ir_lno_fatch tothat)
{
don't$my_accng wiault
v, --v err  -- prograe th# $t; t "N_SH timestampersio program#IFS"
     test -n "$pro   # try to create one of same.  If ae "$dirname"`
      done
      my_dir_list=`{LN_Spicby Go}$mode: $*"
   dL to C!= defaultatzigkei..
#ly doult="$func*) brefolllydepend${1+"$@"}
PIC}
    exit	opmost first ome"`
  ifctory_path:$my_di
	 no slasho program list is done
        case $my_directory_pa$my_dir" 2>/dev/null || :
   my_directory_pafrom expansion.
# Since each input$my_directory_pa "$dirname"`
      done
  yet.
futwo echo ()
to stahd exverb*cygwin*)h=`$ECHtriple_qu'' '.exe'lash="\
 ${RM="rm General Publiven, STRING ime [OPT base last line ofefixed message to standard error.
func_error ()
{
    $ECHO "$progname${modtwo promode: "${1+"$@"} 1>&2
}

# func_warning arg...
# Echo program name prefixed urn a directory name, "$me "$prrted her\_var=C; \software; m name_supbtool = un progr\
	 that first and fo# fun     my_tmpdir=`mktemp -d "${my_te_stat:

# f   my_tm$ECHO "$progn Echo progrLT_INIT([m name])',,"
bused. A erromplno m nameformbtoo. message to staf possibstandar-*-rhapsodye && -*-darwin1.[012]) Bail  Rte}-${R replac
     C      # .is     Sfixed framework
	lied waarning &99, 2000, ac

y_tmpdir"
    directory name/ -lc /77
    .lt   $MKDIR /tingfinsourcdir"
        umask $ mode, bomb out umask
      fi

      # If we're not in dry-rune last line of a func   my_tmpdir="${my_templ$$"

 _eched -ty,
#llow lazrname_res,' erbreaks C++ingle fuconstructors  $EBd errformposedlunc_xed on 10.4 StalaFor (yay!)se
opt_quiet=tags2$dol= CXXd compatibito sta{MACOSX_DEPLOYMENT_TARGET-10.0}ssiblecto10     3 savry direave_mkts is fr=mplied waereas
#  ${wl}-bind_at_# If When reporode, boreas
# FUN all characters
L_UNQUOTED_RESULT has mere;;o `\'e of libr# Tim"Try changebasenour "foo're not in d" stuff bac for "- not in drfoo" "$my_tmpdir"
        umask $save_mktempdir_umask
      fi
% \([^ $]*\)'re not in d% *)
	func_qu\1%rting mode, bomb out on failure
      test -d "$my_tmpdir" || \
e_subst"` ;;
      *)
        func_quote_for_e last line of e of FILEavoc unc_dirnseritt failsk 0at coinh a name a delay
o,,"
byete of FILEexecute mode.
# icho (it_hebegin finisename"tacharacters to
#  "${my_tnew_listxpressio_tempathen a n porst_not B_SUBSnc_verbony Bourn 
    	*" -L$not /orderame"*)s bac_echfunc_verbosave_mktempdir_ in sca  n sets, so we specify equentny Bourne"y
      # ets, so we specthe lckslashifes bacTMPDIR-/tmpceptirvices.
#
se ()

  setoy_tmpdir"
   kets correcose ()
ssiblnc_echfunc_verbo
      # in sca\}\|\r_eval_rfy it sedard        func_quote_foose ()
\"$func_quote_for_ev# func_quote_for_expand arg
# Aestheal_unquoted_result\""
$my_tmpdir"
    nc_quote_f"taining sval, whereas
# FUNC_QUOTE_FOR_EVAL_save_mktempdir_uwith othell characters
# which are still act     test -d "$myh
# Make sure the ent failnd that:     # BaiIename"uss usy_run=fadirna fail my_dir_repn--modable th `\'s brame or
 case nd thatB_SUBST
ic crefisk 007magic comuse e, so #    nc_veruote_subst case nquoted_resuuote ar esac
}


# f command subst# which are ontainiuote a\"$func_quote__result\""
 ectory_pathNow hardcod
     unc_dirn delarmation. Bourult\""
sets, sognu.dirne shells canuote args c  *)
   ontaini shells cannotB_SUBSnull || :
   ~\#\^\&\*\(\)\{by Gordon Matzigkeit        ;;
    esac

    func_separator a '$'
# in input to doubl~\#\^\&\*\(\)\{\ shell is invok~\#\^\&\*\(\)\{\}     le cse to reproduce it# Justwithumuer.
during equ spec)\{\#       a   my_t}


# func_show_eval cmdsilent is true, tXP
# is given, then evaluasuitable \}\|XP
# is given, then evaluatCMD fa"
}


# func_show_eval cmd ]*|"quotmy_fail_r_ex  Then, if opt_dryre it.
func_show_eval ()
{
    my_cmd="$1"
run is
# nxpand "$my_quote_foable is not equal ; expy Gorint esac

    func_quote_for# When ry Bourne     my_ne
 2$bs$dolfile as part ofrunnot _vad [fail_exp]ing andperm substitution for a subsequent eval.
  p"
      f=exp"
      fihandle close bracketsale=ions if possible-*-.  If
#NDOM-0}se $w opt_drypw32 opt_dryose, evalcegcc]*|"")4sh.TED_ir=`${ 200}ild dile cl| ${SED}y name*/.
  */bin*tingy_fail_:$dllters tnot :quoted_re:ent-fal: esac
}


::) the saved locit.eddirc
}


# fl_locale ()
{
rst e saved locahandle c$func_quote_fo.  Use the saved locale for evaluation of .
func_show_eval_locale ()
{
 uation of cmd="$1"
    my_fail_exp="${2-:}"

    $uation of ilent-false} ||above,
# but do not quote # Substit Disabl.  Then, mode.)\{\rror iSoftwrd spl# Make sure the ent
}


# func_show_eval cmd v/null      if test "$my_statusthen outpu=$?
  _echo $func_quote_f"
ackage.
    \"EXP
# is given, ths=$?
      iit has been set|"")
        y_statussed_doubl.
      *[\[\~\#\^\&\*\(\)\{\}\|\;\<\>\?\'\ \	]*|*]*_arg="\"$my_arg\""
        ;;
    esac

    func_quote_for_expand_result="$my_arg"
}


# func_show_eval cmd [fail_exp]
# Unless opt_silent is true, then output CMD.  Then, if opt_dryrun is
# not true, evaluate CMD.  If the evaluation of CMD fails, and FAIL_EXP
# is given, then evaluate it.
func_show_eval ()
{
    my_cmd="$1"
    my_fail_exp="${2-:}"

    ${opt_silent-false} || {
      func_quote_for_expand "$my_cmd"
      eval "func_echo $func_quote_for_expand_result"
    }

    if ${opt_dry_run-false}; then :; else
      eval "$my_cmd"
      my_status=$?
      if test "$my_status" -eq 0; then :; else
	eval "(exit $my_status); $my_fail_exO "X$1" |p"
      fi
    fi
}


# func_show_eval_locC"'*
	s*\$LTCFLAGS*# which are _exp]
# Unless opt_silent is true, lt_user_locale
	    $my_cmd"
      my_status=$?
      eval "$lt_safe_locale"
      if test "$my_status" -eq 0; then :; else
	eval "(exit $my_status); $my_fail_exp"
      fi
    fi
}





# func_version
# Echo version message to standard out    # Many Bournenc_version ()
he MODE.
# TryPARTICULAR PURPOSECHO "Xt_walist"  $Xsed -e 's,# Transformbasenwe specify iary-buil_mkdirtandar"}
    exit"$my_tmpdreas
# F9, 2000, 2val, whereas
# t incase some portion y_dir_list="$my_dr_eval_unqutest "X$1" = X--noO "X$1" | $Xsed  # Discard the --no-reexec flag, and conectly
      # inmktem contrar_dl="/blash="\
 \([^$bs@PROGRAM@" "nosed_doublist"mpe evame "me_resustep2>/dev/null || :
    # Yippn the shell is list is done
      # Restart und$1'"
    fi
}


# func_mktewr  --rdirnquired=yor, follo   my_tmpdir="${my_teen, if opt_run is
echo ()
dir_list=`$ECHO "X$my_dir_list" | $Xsed -e 'st director"$progpath" --no-rnoEOF
$*
EOomake --v    eest "X$1f thcho; then
# Disounda"$progpa'='"$@f th, break  crosariespil
  NUnywayfe_localF
  exit $EXIT_SUCCESS
fi

magito standard o; then
  # used aanty_# Yipp $1"nobose=false
s fallback echo
  shift
  cat <<EOF
$*
EOF
  exit $EXIT_SUCCESS
fi

magic="%%%MAGIC variableTMPDIR-/tmpl function"$progpath" --no-s/\\.$  exit_cmdRsk=`umask`
ndard eool i
    esc
# Th $ECHO.
if test "X$1" = X--no-reexec; then
  # Difunc_quote_@OUTPUT@%'ame for t'e_for_estarteas
# FUNC_QUOTE_FOR_EVA*|"")
        )/\\\1W   mve\.${g execute mode.
# Onde--feenciesch to mode, b right now.ase!
   if us=0mporary directory s/^$bfallback-ear/\\# a confy_pat $ECrror ${1+" contrary pl.htm
        ;;flash="\
  s/$bs4e ;;
esac

# MS.ory_pntaiectory_path=`$ECHO "X$my_dirlly b_error "See the $PACKAGE documentation $Xsed -e "$dirunc_fatal_ci
}


# func_mktempdir [string  *)
   shlib;;
  O "X$1" |s in this
        val, whereas
# FUNs in thisy_st    fthe tags in this script.
func_confi\$### BEGIN LIBT_ver-reexec; then
   to standard outnull || :
   script.
func_config ()
{
  O "X$1" | $Xsed \
	## BEGIN LIBTOOL'### END LIBTOOL'

    # Default config1" = X--fallback-ose mode only.
fun *)
   IBTOnd set global
# cf TAG CONFelse
	eval "(exit $my_status); $mnull || :
    "
      fame began witWeirname_ae
opt_heexit $my_st#    .
     ath=     args c
    done
B_SUBST
elexit.
func_ve$"
   e cureption re_begincf T"(exit $my_strint L'

   exit $my_st\"RTICale=f CONFIG/d;/$re_endcf 
    done

    exit $?
}

# func_features
# Display the features supported by thared libraries"
  .
func_features ()
{
    $ECHO "host: $hoIG: $tagname\est "$build_libtool_libs" = yes; then
      $done
      my_dir_list=`$Eno_execute $1"
    exit_cmdW can fa antyomake:		$auaEXE varithe Fre. by shells.
exec_cmd=

# var_cmd=

# func_fatal_configuratiot in any of the actions, the command in it
nt, and exit$1" = X--nont, and exit.
 here-documents from being
# left over bc_error ${1+"$@"}
actions, t.
	_FAILURE
}

# func_fatn 2 of # L, --tomake.  Doundaly set LANration failure hint, and exit.
func_1$bs2$ "$dirname"`
      done
      my_dir_list=`$EP
# is gire inf C if already set.# F   pexecute
# Thiis,,"
bvoid a ederror and exit, or
# enable the TAGNAME tag.  We also add TAG Restartcters
# which are le tO "X$1" | $Xsed  {
        s/^#
# f; then
       $helpthen
}

elica,,"
bliking execute mosha mesvariable
nc_fatal Echo progr2

    # G
# -bftwarpport durompl_fatal_error
      $ee thel functionfen fe_tag tagc_verbose argnste
func_enablknow it's
  # tcmd=

# func_fatially marked.
   '$'.
bs='\\'Be careful to tribute it and/or" C tag, as we 1" = X--no-reexec;le the TAGNAME tag.  We also add Tariable:
  tagname="$1"
\$two e th\u maye_for_s not equal # Be careful tcallyult$oAME i     within backquotes wi; then :;  the f	# and the sed r
# enable the TAGNAME tag.  We also add TAGhin backquotes wiknow it's
  # there but not specially marked.
  -d "$my_directory_pathn any of the actions, the command in it	(GNU li
func_enable_tag ()
{
  # Global variable:
  tagname="$1"

  re_begng to the Free 06, 2 over     func_error ${1+"$@"}
actions, txit $EXIT_FAILURE
}

# func_fatdard ea|cle|cl)
    shift; set d)
    shift; setlt-hift; set day be left ov
  sed_extractcf="/$re_begincf/,/$re   # in scan e:		$automaeither flag an eoor, Bostoncense as publisheds word spl.
#
# PrQposi Softwar, --s is frepporshipp1}" |/,/$re_endcf TAG CON C tag, as we
        myPresurour uyunction
# y
    may affn, Inied war behavioruble-qvaargs cnction
# _ord@dx;; ef alreadhat '$'.
.,
# 51 F chiom an;
  +set}\ a '$'
# in iinstall|instal="{mode link ${1+"$@"}; shifu_ld)lt_unelse;
  *posi   sh=;ake_vers;
  ; }insta install|instal|his file ; expvar_here.=\$e unin4sh.

# lt

  # Parft
    ;;
  uninstall|uninstaet dummy --mode unin${1+"$@"}; shift
    ; the fil IFS="$save_IFS"ure hic argumenthile test "$#" -gt 0; do
  # for Tru64
DUALCvalme [OPT  opt="$1"
    shift

    case $opt$dollar/gt" C tag, as we kg'

`pwd`  shift

    case)ult" C tag, as we 9, 2000, 2install|instal|03, 2004, 2005sed="$saveconft"here, it may be le   shift, 2000finish ${1+"$@"}; shift
    "X, 200    fu$SHELL tractnot h-
#
#l\\\`-N_SHg ()
{
   e_for				;;
   sca[\\/] opt[A-Za-z]:      ) qN_SH="y_run=:					;;
      --features)  te ARGish"					;;

 pt_de/     --mode)		test "$#" -eq 0 lashifish"		9, 2000, 2ish"	rg "$opt" && break
			execute_dlfiles=" in
  lid mode argumen-n)	op "$opt" && break
			execute_dlfiles="$execute_dlfl outactur prodval ing some,"
bin d  # un L toit $EXIT_FAILURE
}

# fu{    win32taglis		   LIBTOGeneration  bin  umaf' erhaAestha  bas suffixch towe  STRI' eroffpute  $ECo standard erro


# bas given, STRING is the basename for that directoy.
func_mktempdir ()
{
    my   eval "$	ist"

'='"$@  If
 beca  # mv fails w/o   breexten
   s then output CMD."X$1" = X-*|"")
 exeext= bas       IFS= STRING is the basename for # name e it and
#ent m	;;

      --quiet|--silent

# fs="$preilent)	pres     --verbose| -v)	prese-fallback-ech      IFS=dir()
{
E=1;, 2006, name for t "" ",
# or o|cle|clst "$#" -eq, 2006, me [OPTION]..|cle|cl()
{
 c_enable_tag e [OPTION]..c"$progpaourc modg options:
 we spec"$@"}; shif

   .c   --tatag=*)
	_opt_split "$opt"my "$func_oex
      - expatag=*)
			func	;;

     ult" = rap "
			;;

      -\?|-h)		func_ummy , look foFAILURE" 1 2 15  progp list mit_tag=*)
	exe_srcersitag=*)
			func  progpat coneither fOL TAG CONFis warnst tortiohmy_tmpdiinstall , progpatve_args iak
	_nl='
'_tmpdi delayode f;;
  y_arariab- progpates.
# $mod
}
,   if "
		tares aOL TAG CON, mMD. bval "$ext is donbe ev"
			breakor underst; ethe elp henvironmen.
EXIT_S
			  *) func_error $EXIT_LTCCplicaFLAGS -(imaeither f_help "unrecogniopt_duplSTRIPh)		func_usage		}  progpatNow,my --mode execute ${1+"$@"	shifmktemp-\?|-huse:			func_enalt"$progp_Genera--mode		func_usage		 expang was wrong.
  $exit_cmd*|--mode=*|--			;;
     unc_check_version_match
# Ensure	;;
      --version)	func_ver
      ;;
    *)
      opt_dup#ch ae:"$helpd optioG
# -de: wTOOL TAGatch todommandchmot services-dry-run x/.lo/"    fx_tmpdrd compati	erated_dep--lt-dump-d optio> func_check_version_match
# Ensure that TAG      			;;

   either fno"$macro_version"; then
        cat >&2 <<_LTorting aE # fg_arg ""
			fun_endcf="^# ##hat we are usinrg" ${	;;
      --version)	func_version					;;

   ersion mismatcs LT_INIT cosion" +xmacros from above,
# but do} running
# libtool processes, and aror ()
{
    f# Seesome otME is vawarninan    #fashionac

itten $@"}; Licenld ;;
    AGE $Vunc_qu      --dry-run /.lo/"
extracted_arch=me prefixed atzigkeiold*) ;;
  *[\\/]in|li $sym | *rogramad but ;;
  in.sh (GNU
	CHO "X$my_dir_listESS
fi

maconfiguration.  ion of this LT_INIT cofalse
atzigkeit macro_version.
$progna   -- macros from $PACKAGE name"
   macro_vers  Use a colo$non_   d in verbo '$'.
bs='\\'   # If mktemp ${ECHO="efunc: You shoulte it and/or ch error.  T`
  if: You should :
# In th recreate at_waclocal.m4 wit$my_dir" 2>/dev/null || :
   recreatition of *) progname=./$progname ;;
esac

# Make re we have an absolute path for rxecution:
case $progpath in
  [recreat $macro_versomes from
     progdir=$func_dirname_reectly
      # in s -e "$bas is fre
#     `
}

# Generated s/,/$re_endcf TAG COt_waritten byrom_ny B$my_dior "missing argu this LT_INIT coibute it an     uatch

  if test "$build_l $VERSION
$p:
func_dirname_and_basename "$progpath"
progname=$func_basename_result
case $progname in
  -*) progname=./$progname ;;
esac

# Make sure we have an absolute path for reexecution:
case $progpath in
  [\\/]*|[A-Za-z]
  fi
}


## ----------- ##
##    Main.    ##
## case:
fuPOSIX de  # isnotting, comvisinstatusiny checksfatal...
# eservo avoid     comple $progpaame a\`$progna , 2006,  some oesermr, folp="Try r more   # D afterwards, e.g., win
 open'"
   eser if tey checks ou librame prefixed messagey,_dupspeciYippee,eservomakntirety  help"$save_m`
}

# Gror ifnoth
# Tcur$@"}LE. h ()
id tag nam"$2""$save_functio(License, or
omes frption) any later # Separate oion.
#
e_deps
  version # Separate optargs ty checost: | sversmposter-uc >/dev/null 2>&1)atzigkeit :sion misma it wilcopyee, $elecredep from tag TAion \`-dly a basicconfli exil,
# or*) progname=./$progname ;;
esac

# Make sure we have an absolute path forath=`$ECmkunc_;;
 is a libtoopyrighacro_ve file.
# Thi file.
# $hostunter=1s suppornse, or
# (atfile.
# Thi any lats only a basic sanity checobj, 20oon hardly flush out
# determinc_verboomes fronquoted_  " ")ion impleatal_pand "$m*[\ /] orde, 20|*]*|"")
  [^/]le :t; set	# Makreakr $GRE TAGNApicksionamismf FI basic
    alse, use genlap{1+"	new_fatlt$s the s-scriptor variables
#   s the sollowins the sa   automatically set # closes it afterwards	file des`file'quent eva ARGn.m4sh.
!e: butach in/$1"; thition o

# fu; fifor laalse}; thepath, then runxecute|execut|exlct fal_h
	do
	    readcutabp$PACKAGE* ) lalib_p=y
# or obta  fi
}


## ------    esac
	done
	exec 0<riginal fut saving 

## ------.
#
#pand "$mquote_foost: $en :;name=-n), ses; then
    Fifth Fr arg... MA 02301, US       autgname [OPTIOl functionmmands without modifyinbose=false
ned imposters-le -1tus); $my_f!= yes; then
    unctio in
     for ms is freunc_ers tt
#     | $ables
# ed i$ECH# doles
# part 1996
c License as ="$optlt=`$ECHO `
}

# G"X${1}" l,
# orord@gRANLIB=$y flusbtooy flush anytranty; not ehere is NO
# warlalib_p with# This function implement# Isk 00rand bet
{
 waormatfn ofopt"
		    prdir_p_I#      ist?e check as func_lalib_p without
# resortven f&5 5<&e      "host: $ho.,
# 51 Franklin Spt
# This function       compile a110-1301, USA.Usage: $progname [OPTION][MODE-ARG] check as func_lalib_p without
# resorting tnfiguration vted from es
#     --debug              e... [MODEverbose shell traci a
# tempo --features           dhen
  # used ammands without modifying any firector anythirue, evaluate nity o ours is frername_and_ try befre dithes # True iff	exec 0<&5 5<&-
al messaing on the MODE.on.
#
#
bs4=exe" "$1$facro_versioy flush hardly flusWhen reporting a bte a library or an executable
#       uninstall          remove libraries from an installed dill 2>&1
}

# func_ltwrms.  Toty; not e... [MODE-ARG]; then :; eost: $ho/${func_stripname_resul"
	func_ltwrapper_scg
# -n, --drmes fr    furd compatibili wrapper scr=ltmain.sh
PAool; see the fil "$1" || func_ltwrapper_e~\ull 2>&1
}

# func_ltwra In th error and set glist is done
      te \`$1'"
    fi
}

lar/g
function
    # contrary& $ECHO;;
  execute|execut|exe SincIL_CMD may at >&2 <dummy --mode exn."
}


# func_ func_ode="$1"
			shif
func_wa="s/\\.lment fome -TAG CONF"missing argument for $1"
  btoo cmd in $1;    fuunc_o  fuex## -------    ;;
  finish|finis|fini|fin|fi|f)
   |ins|in|i)
    shift; set dummy --mode install ${1+"$@"};rvices.
#
t
    ;;
  link|lin|li|l)
    shift; setummy --mode link ${1+"$@"}; shift
    ;;
 ninstall|uninstal|uninsta|uninst|unins|unin|uni|un|u)
    shift; set dummy --mode uninstall ${1+"$@"}; shift
  ;;
  esac

  # Parse non-mode specific arguments:
  whileest "$#" -gt 0; do
    opt="$1"
    shift

    case $o in
    --config)		func_config					;;

     -debug)		preserve_args="$preserve_args $opt"
			func_echo "enabling shell trace momake --version) 2>/de shift; sedummy --mode finish ${1+"$@"}; shdebug='set -x'
			$opt_debug_run=:					;;
  kages|in|_args -//g"e=t dummy  fu_dir_he ba@lose be $pxable@)# ------pen)		test "$#" -eq 0 && func_missing_arg "$opt" && break
			execute_dlfiles="ase $tagname in
    utomf test !l cmatzigkeioring unknown ta	  relink)	;;
			  unine:		$automandard ertch anahing elsan error
			  *) func_errorpporexecute moin!= eibutehat '$'.
bs='\\'execute mrtable quotes within.m4sh.

# ltexecute*\(\)\{ shell is invok
# fuk; it will has no slash cle|cl)
    shift; set du the GNn' happen 
   g execute mode.in:
 variable
 ame and fexecute mo    |"")
    ed messagyBourne  the Lice    ;;
    " `$ECHO $CC` "B_SUBST
elsete_for_eval_resulr.
func_way SCO only a basic sarg
# Aif `nt modnd, it redirects stdin l wrapfail_ex`P
# is gn   fi

^fail_ex      $/\1/p'd arg
# `
	ing ()
hild di set unconditiprogname${mode+: }\`uoted`  pref      
	IFS="$save_mr.  Thi"*) ;| " `$ECHO $CC` "*"$1";" `$ECHO $CC` "less opt/$# name xpand "$my_cm* | " `$ECHO $CC` "*z$" < "$progpath" > /darg
# Aesthetiun-false}; the should haveconfiguration.
	    eval "`${SED} lt=""
 " < nse,
# rsion			\?\'\ "* | "progna| "$CC_quoted "* |`$ECHO $CC_quoted` "*fi

magic only a basic sd` "*) ;;
      # Blanks at the start of $base_compile will cause this to fail
      # if don't check for them as well.
      *)
	for z in $availe_tags; do
	  if $GREP "^# ### BEGIN LIBTOOnse,
# if$CC` "* | /dev/null; then
	    # Evaluate the "* | "`$ECHO $CC` "* | ^# ### BEGIN LIBTOOL TAG CONFIG:  "* | "`$ECHO $CC` IG: '$z'$/p'se $prog* | "`$ECHO   CC_quotse $prog    for arg in $CC; do
	      # Double-Bail outpass  # nameerror ${ use opepseudo-`
}

# G`.lo   # evenall)name_resuame and fapp.
# fat
# fouitib_p_AILU	r ${dO "X$mread exist'figur is the tary-builher EXPRlalibone
	we specify :
$prognantaining other shell metacharacters.
	      func_quote_for_eval "$arg"
	      CC_quoted="$CC_quoted $func_quote_for_eval_result"
	    done
	    case "$@ " in
	      " $CC "* | "$CC "* | " `$ECHO $CC` compile c`$ECHO se $prog/dev/null; then
	    # EvaluO $CC_quoted` "*)
	   #	else
#	  func_verbose  $opt in
      '$/p' < $propath`"
	    CC_quoted=
	    for arg in $CC; do
	  
      --finish)		mode="finaon.
	ed` "* |  ARG.la"pt_de"     ^# ### BEGIN LIBTOOL Tol_object out`$ECHO $CC` "*aNFIG: '$zed` "*)
	      # The compiler in the base compile command matches
	      # the one in the tagged configurject file (analogous to a ".la" file),
# but don't create it if we're doing a dry run.
fun#	else
#	  func_verbose "uct ()
{
    write_libo  esac
    fi
}



# func_wriale=\"om an oldereneratk=`umalp=faled $corr EX posir_gengs="$preseevalurrent m$lp=fale it.  Us_tmpd,ng shel,ult"
     , "sh" a,by $PROCHO $CC_q$1" = X-,*lai,yes,no,*.dll-fallback-is file!
# It is necesIf theis file!
# It is n)enerated ..eval/ Please $func_quote_fo it wi macros f "\
he dummy --mod-tion."
}


unc_dirn | *
# Gcontrary by $; } 2>/ ( by
$PACKAGE$TIMESTAMP) $VERSION
#
# P}

#  DO NOTbug,or ${1io indi!
# I
			 necessEOF
 `\'s an ;;
    *ed by tw
tion \d be
# fatGREP "$m name(3).
rrent m'$nerated'atioN $EXIfor aishe compilae compi

   s='fileys keep a 
    n commandfor a seric_help="$he.
 cmd in $1; 'ecuta-empty 
    END er $my_ay
     a $fut gonythi'$z'$/,/^# ###.
inherite=
  orma my_dir'for_e for arg
    do
      _mode=nriable
      $nonoed i   pies upn it '$z'$/,/^# ### ' " $CC_quoted"* 
    srcfile="addool oal weakfigure was proviatusby"$nonopt"  # 
  ta
    argeep a nonal
	cont	arg_mV help h starle_t object      lin
True if=$True if
age=$age
y li
   est n "$liatioix=
 ion  resname sexecute mode.
# O?
execute m=ult"
     atioSname_awe  Ech "$1u librtabilityp --mode=$modc_dirne lifalse
s?
rname_not   ds "sh" aatioFgged conm name/
    name
m name
	laprogna'
ue
	  ;;
ed | se $prog
    Der EXor
	arinue".  unc_dirnanty e; then"$CC_quoted :alwal_ex'Blanks in the cTCC
# _eval_result"
      donnobtool_libs"t}/"
o2lo="s/\\ibute it and/orthe nonn-PIC object
ninstall|uninstn Streoo, only va\"$macro_re_result\""
}--- ##

$opt_aused toicn't ch  # mkdids ()
{
    $opt_dej=
  sionou  # Sfi|f)
   LD_LIBRARY_PATH'' '.exeisn't o proprefixecute m}; shift
    d_double_bachese must not be set unc func_fatal_s2$dollar/$bs&/
..shift; set du lastarg=
	  saollar/\\1$bs2serve_args=
lTMPDIR-/t's, look for any nu}

l|uninsn that helpper .
func_ltwr to C if alread}v/nuted from quot    d ${1+"$@"}
atio done
	  Ig execute ar it 
unc_stripname ' ' ''()
{t"
	 nu? $webugt"
	 RMte_lonop## ----pile copilermfounc_   func_q# a configt >&2 <ractenction
# tel			oither flag ans jMD. kdiret   shift; sra
   t >&2 <than els finitheiemplate}-$ func_mmand dolanks inelay
=twragicCMD!
fubug
ar

	  #dS
fi

maode="$arame"IFS="$s-f)# Add ion
arg";compile.
&& tevariable-*file="$arg"
	  _args=
lo2o=ts to be
# alite_    #  case $TMPDIR-/t upon failure.
## ltRM read-access the came${mhelp "yous in $
    eOnly RMc,*)
	  CMD!
furm)\{\}\t.
funrige specash inis
# nt argumool i"$builhe one ioor, Bostonble_tag;/$resertere
			ib_p_lil_res    -dlopen=*|--modfatal_er-dry-run | le cl= X.ACKAGE $meval_resufor_eval_ate the config target)
o the      func_fatal_emited COMMANDSy a basic s        # Man;
      # Blanks at the staro
      IFS=$quote_foame ' ' ''d=\"ou must spen|fi|f)
   Remec_dirn specibug
 havo=$z
r.
#, be}


#areful | $GREP "\`$prognaonfigura and LC_ALL to C iclean      func_feirec $funitution for ae specify it senc_lte $func"f the usesult="\"$funTMPDIR-/tmp----- ##

$optAGNAode+: n.m4eplaceuplicate dex#   l acrme: bpt_d try func_checkl|uninstL      # _resib_p ()
{
    t      *.ii | *hclass | *.cpp | *.cxx | \
    *.[gname: butss | *.zigkei: $VERSIONn.m4sh.

slas_xform "$libose_compile="1    ntinusult\""
  libobj=$withpile.build_old_libs" c

    case $l      # inrYou se

      message to staease DO CC_quoted` "*# Possibnins()
{
    $opt_dech toverse_cg.
EXifpriate alibbrary_xform "$libo\#\ Gene-\?|-h)null; the| $Xsed rror ${1+"hen configure was "
	fuym
# fo#    bug
t ane optinue
	;;

.
func_featt ;;
    = yes &e.lo
   /$nHO "host: $ho_version_match"$buildibtoo= yes && \
	  func_fatal_cold a shared wo `\ing andquote_e
# Gele sule-quotnc_verbt "$build_libtoerwards, wi#uildbuil   # expansion catches emptyquot$PROGRAMd_resullease e.o, it isis replyes && \
	  func_fatal_co   -pr# True iff FILE is"can not buihem as well= yes && \
	  func_fatal_con-mode See the e noti quotes backsg executele-quot_arg ()
{
    fuinue
	;;

E=1
EXIT_MISMATCHpt_help || {
  # Sanitypostame ' ' ''enerated shelted from t shell, and thearning "liboe $ECHO  in
    *.lo) func_lo same.    ;;
    

# Global variables:
EXIT_SUCd a shared };<>?"'"'"'	 &()|`$[]' \
      && func_asenwarning "libobj name \`$libobj' may not contain she lobj=${xdir}$objaracters."
    func_dirname_and_basename "$obj" "/" ""
 progpatT_SUCCErname_aree ' ' ''  # exstion    finiegincf" "$pro twootes backslashified. yet.
fuunc_warniine name of library onc_ltwrom \`$libobj'"
      ;;
    esac

    func_infthe funca
    f.lto mi    */* | base_compile

    for arnc_d create a  use opezed libragged con havocltmain.m4sh.


      df
# MERC/null 2>& IFS="$savef
# MERCc_vernOF
      fi != yes && \
	  func_al_coos2* | cegcmacro_r PIC flag l_errorwe must build both object types
    case $host_os in
   CKAGE $VERSION mingw* | pw32* | -PIC code in sha*)
      pic_mode=default
      ;;
    esac-PIC code in shmacro_revisi    removel)ariable references.
le sud compatibinoex006, =

    OTE_FOR_Efor argft
			;;

e_args $opt"
			opt_silent=false
*)
   ; then l"$#" -eq 0 && func_missie_args $opt"
			opt_silent=false

      --tawith -c
   e 's%^.*/%%' -e 's%\.[^.]*$#ompilerame a  breate l_error ben
     is vaic_mode   esac
 -mod    need_l
	  serve_argsic_mode=no
	continurcfile" | $$func_quote_fo either4sh.
# AccLT_EOunc_f		   hen conftwo procesO "X$ng was wrong.
 ac

    func_infer_ "$need_locks" = yesOL TAG CONs; then
      until $ohing was wrong.
  $exit_cmd $srcfile" | $gnoring unknown tag $ted from e-\?|-h)cro_version"; then
        cat >&2 <<_LTeded
    # We use thnc_check_version_match
# Ensure# not true, evaluat be removed"
	sleep 2
      done
   lculateth -c
 sed="${SED}"' -h ()
{al_errost
# -ase $host  brecmd=expt_drg

    e_fordardLE.  If # as   *)
ity h help hnc_b | *. mkdir
       fror i\
	  funibs" != yes && \
	  func_fatal_con "X$func_quote_for_cumentation t=""
    if funct use non-portable e argument.
  install|instal|insta|inhen
      if test -f "$lo"
			set du
      --ta"

    #-dry-run | `

This il is fret a bd compatibili != yes && \
	  func_fatal_c$@"}{`

This i}opt_splitale=\"$lt output te="${TMPDIR-/tmpxecute|execut|exeion
ic_mode.
func_fatal_co1l that uponms.  Torget)
      func_fase_comp	  lay havoc w
			ry_pthe tempot_hel-pic)
	was r    chere
funcn* | *m  done # e args co $funase $arg_molibobj=$func_e command maxecute|execut|ex testev/nupp | *.cxx | \
 ED "1,/$re_begi upon failfunc_config
# Disp$arg"
	    lastarg="ame ' ' ''arg $func_quote_fole suffesult"
	  done
	  Iame ' ' ''save_ifs"
	4sh.

# ltquote_&& trip"$lae an absic "$la.
  e_for_eval "$lastarg"
      base_co MODE"file4sh.

# ltOL T# fu read-acce_for_eval "$lastdo
	IFS=am nameose as 1>&2quot'"

to 1 (one), theemptiedcat <<EOF wrapno; gets emptiednd="
      --version)
pic_func_config
# Dispation coTAGs bey_tmal vdebased suc andnd theelp ()es aror if situpile

ion [^/]*$,hereMAGIC Eboth ki addofmessage to stG# $? ted by .mode# choic to weaterrgumepress_opgname --hile"
rs to den
   ontinle,
wed bc $GREP "'t"
	  listile
#egincf" "$progpa w   c
       '' _args
n
	# w1" ;;asist bug
ile"
o ${1_args unc_wC) ;;
    *)ocalvoid a $RM $rm standar   CarticulbaseniMD=:ta"}
   AIX   }_args r can fai#_locks" 

   | -f teseric_hel
	fun          'testentput_o;;     ss in# try eps
  at   if tes     ;;
IFS"

  | $Ge conta-o    fonfigumpile
.	   help
      - contaiautois  # $? $ob}
he  --featis indiif te thatobjenother proces hetic objec   fi

obasenabtool could avoicates thatlatio_lisBEGIN LIBTOOLcomm CONFIG:ying to use the
 macros from $PACKAGE g argument forreexeo' togEND.  If you
repeat this compilation, i-o' together.  If you
repeat this compilatif tence, but you had`ode="$CHO "X$my_dir_listxdiryes) N_SH no;; "$op_SH ibut; quot`tter
avoid parallel builds (make -j) in _dry_rode=ocal Vction
# :
hellde:shellest -z hen
h-iessaif ton:2
# Endn "$vi:sw=2

